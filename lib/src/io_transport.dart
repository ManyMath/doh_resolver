import 'dart:async';
import 'dart:collection';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:socks_socket/socks_connection.dart';
import 'dns.dart';
import 'resolver.dart';
import 'wire.dart';

class SocksProxy {
  final InternetAddress host;
  final int port;
  final SocksCredentials? credentials;
  const SocksProxy(this.host, this.port, {this.credentials});
}

class IoDohTransport implements DohTransport, DohWireTransport {
  final SocksProxy? proxy;
  final InternetAddress? proxyDestination;
  final SecurityContext? securityContext;
  final Duration connectionTimeout;
  final Duration requestTimeout;
  final Duration idleTimeout;
  final int maxConcurrentRequests;
  final int maxQueuedRequests;
  final bool padQueries;
  final bool reuseConnections;
  int _active = 0;
  bool _closed = false;
  final _waiting = Queue<_IoRequest>();
  final _running = <_IoRequest>{};
  final _idle = <_Lane>[];
  // Lanes fork from here: forking from Zone.current during a queued handoff
  // would parent each new lane on its predecessor and keep the chain alive.
  final _zone = Zone.current;
  IoDohTransport(
      {this.proxy,
      this.proxyDestination,
      this.securityContext,
      this.connectionTimeout = const Duration(seconds: 5),
      this.requestTimeout = const Duration(seconds: 30),
      this.idleTimeout = const Duration(seconds: 5),
      this.maxConcurrentRequests = 8,
      this.maxQueuedRequests = 64,
      this.padQueries = true,
      this.reuseConnections = true}) {
    if (proxy == null && proxyDestination != null) {
      throw ArgumentError('proxyDestination requires an explicit proxy');
    }
    if (connectionTimeout <= Duration.zero ||
        requestTimeout <= Duration.zero ||
        idleTimeout <= Duration.zero ||
        maxConcurrentRequests < 1 ||
        maxQueuedRequests < 0) {
      throw ArgumentError('Invalid transport limits');
    }
  }

  @override
  DnsOperation<DohHttpResponse> start(Uri uri,
      {required int maxResponseBytes}) {
    return _start(uri, maxResponseBytes);
  }

  @override
  DnsOperation<DohHttpResponse> startWire(Uri uri, List<int> query,
      {required int maxResponseBytes}) {
    final List<int> checked;
    try {
      checked =
          padQueries ? padDnsWireQuery(query) : checkedDnsWireQuery(query);
    } on DnsException catch (error) {
      return DnsOperation.failed(error);
    }
    return _start(uri, min(maxResponseBytes, 65535), checked);
  }

  Future<void> close() async {
    _closed = true;
    for (final request in [..._waiting, ..._running]) {
      request.cancel();
    }
    for (final lane in [..._idle]) {
      _retire(lane);
    }
  }

  DnsOperation<DohHttpResponse> _start(Uri uri, int maxResponseBytes,
      [List<int>? query]) {
    if (uri.scheme != 'https' ||
        uri.host.isEmpty ||
        uri.userInfo.isNotEmpty ||
        uri.hasFragment ||
        maxResponseBytes < 1) {
      return DnsOperation.failed(
          const DnsInvalidQueryException('Expected a bounded HTTPS request'));
    }
    if (_closed) {
      return DnsOperation.failed(
          const DnsCancelledException('DNS transport closed'));
    }
    if (_active >= maxConcurrentRequests &&
        _waiting.length >= maxQueuedRequests) {
      return DnsOperation.failed(
          const DnsTransportException('DNS transport request queue is full'));
    }
    final request = _IoRequest(this, uri, maxResponseBytes, query);
    if (_active < maxConcurrentRequests) {
      _active++;
      _run(request);
    } else {
      _waiting.add(request);
    }
    return DnsOperation(request.result.future, request.cancel);
  }

  void _run(_IoRequest request) {
    _Lane? lane;
    final origin = _origin(request.uri);
    if (request.query case final query?) {
      final id = query[0] << 8 | query[1];
      for (var i = _idle.length - 1; i >= 0; i--) {
        final candidate = _idle[i];
        if (candidate.origin == origin && !candidate.hasUsedWireId(id)) {
          _idle.removeAt(i);
          lane = candidate;
          break;
        }
      }
    }
    if (lane == null) {
      // Keep the total number of live clients bounded by the concurrency cap.
      // A client is pinned to one HTTPS origin so its per-host pool cannot grow
      // across caller-selected resolver endpoints.
      if (_idle.isNotEmpty) _retire(_idle.last);
      lane = _newLane(origin);
    }
    lane.owner = request;
    request.lane = lane;
    _running.add(request);
    lane.zone.run(request.run);
  }

  _Lane _newLane(_Origin origin) {
    final lane = _Lane(origin);
    lane.zone = _zone.fork(specification:
        ZoneSpecification(handleUncaughtError: (_, __, ___, error, stack) {
      if (lane.owner case final owner?) {
        owner._finish(
            const DnsTransportException('Resolver connection failed'), stack);
      } else {
        _retire(lane);
      }
    }));
    lane.client = lane.zone.run(() {
      final client = HttpClient(context: securityContext)
        ..connectionTimeout = connectionTimeout
        ..idleTimeout = idleTimeout
        ..maxConnectionsPerHost = 1
        ..autoUncompress = false
        ..userAgent = null
        ..findProxy = (_) => 'DIRECT';
      final proxy = this.proxy;
      if (proxy != null) {
        client.connectionFactory = (destination, _, __) async {
          final owner = lane.owner;
          if (owner == null ||
              owner._done ||
              _origin(destination) != lane.origin ||
              _origin(owner.uri) != lane.origin) {
            throw const DnsCancelledException(
                'DNS connection cancelled or redirected');
          }
          final task = SocksConnection.start(
              proxyHost: proxy.host,
              proxyPort: proxy.port,
              targetHost: proxyDestination?.address ?? owner.uri.host,
              targetPort: owner.uri.port,
              tlsHost: owner.uri.host,
              securityContext: securityContext,
              credentials: proxy.credentials,
              timeout: connectionTimeout);
          lane.tasks.add(task);
          task.socket.then((_) => lane.tasks.remove(task),
              onError: (Object _) => lane.tasks.remove(task));
          return task;
        };
      }
      return client;
    });
    return lane;
  }

  void _retire(_Lane lane) {
    if (lane.retired) return;
    lane.retired = true;
    lane.owner = null;
    _idle.remove(lane);
    lane.client.close(force: true);
    for (final task in [...lane.tasks]) {
      task.cancel();
    }
    lane.tasks.clear();
  }

  void _release(_IoRequest request, bool clean) {
    if (_waiting.remove(request)) return;
    _running.remove(request);
    final lane = request.lane!;
    if (clean &&
        request.query != null &&
        reuseConnections &&
        !_closed &&
        !lane.retired) {
      lane.markWireIdUsed(request.query![0] << 8 | request.query![1]);
      lane.owner = null;
      _idle.add(lane);
    } else {
      _retire(lane);
    }
    _active--;
    while (_waiting.isNotEmpty && _active < maxConcurrentRequests) {
      _active++;
      _run(_waiting.removeFirst());
    }
  }
}

// RFC 9111 §5.1: use the first member of a list-valued or repeated Age, and
// ignore it if that member is not delta-seconds. Values beyond 2^31 saturate.
Duration _age(List<String>? values) {
  if (values == null || values.isEmpty) return Duration.zero;
  final first = values.first.split(',').first.trim();
  if (!RegExp(r'^[0-9]+$').hasMatch(first)) return Duration.zero;
  final digits = first.replaceFirst(RegExp(r'^0+'), '');
  final seconds = digits.length > 10 ? null : int.parse('0$digits');
  return Duration(seconds: min(seconds ?? 0x80000000, 0x80000000));
}

typedef _Origin = ({String scheme, String host, int port});

_Origin _origin(Uri uri) => (
      scheme: uri.scheme,
      host: uri.host,
      port: uri.hasPort ? uri.port : 443,
    );

class _Lane {
  final _Origin origin;
  late final Zone zone;
  late final HttpClient client;
  final tasks = <ConnectionTask<Socket>>{};
  final _usedWireIds = Uint8List(8192);
  _IoRequest? owner;
  bool retired = false;

  _Lane(this.origin);

  bool hasUsedWireId(int id) => _usedWireIds[id >> 3] & (1 << (id & 7)) != 0;

  void markWireIdUsed(int id) => _usedWireIds[id >> 3] |= 1 << (id & 7);
}

class _IoRequest {
  final IoDohTransport transport;
  final Uri uri;
  final int limit;
  final List<int>? query;
  final result = Completer<DohHttpResponse>();
  _Lane? lane;
  late final Timer _deadline;
  bool _done = false;
  _IoRequest(this.transport, this.uri, this.limit, this.query) {
    _deadline = Timer(transport.requestTimeout,
        () => _finish(const DnsTimeoutException('DNS request timed out')));
  }

  void _finish(Object outcome, [StackTrace? stack]) {
    if (_done) return;
    _done = true;
    _deadline.cancel();
    transport._release(this, outcome is DohHttpResponse);
    if (outcome is DohHttpResponse) {
      result.complete(outcome);
    } else {
      result.completeError(outcome, stack);
    }
  }

  void cancel() =>
      _finish(const DnsCancelledException('DNS request cancelled'));

  Future<void> run() async {
    if (_done) return;
    try {
      final request =
          await lane!.client.openUrl(query == null ? 'GET' : 'POST', uri);
      if (_done) {
        request.abort();
        return;
      }
      request.followRedirects = false;
      request.headers.removeAll(HttpHeaders.acceptEncodingHeader);
      request.headers.set(HttpHeaders.acceptHeader,
          query == null ? 'application/dns-json' : 'application/dns-message');
      if (query != null) {
        request.headers.contentType = ContentType('application', 'dns-message');
        request.contentLength = query!.length;
        request.add(query!);
      }
      final response = await request.close();
      if (response.statusCode != 200) {
        throw DnsTransportException('Resolver HTTP request failed',
            httpStatus: response.statusCode);
      }
      final mime = response.headers.contentType?.mimeType;
      if (query == null
          ? mime != 'application/json' && mime != 'application/dns-json'
          : mime != 'application/dns-message') {
        throw const DnsMalformedResponseException(
            'Unexpected DNS response media type');
      }
      if (response.headers.value(HttpHeaders.contentEncodingHeader)
          case final encoding? when encoding.toLowerCase() != 'identity') {
        throw const DnsMalformedResponseException('Encoded DNS response');
      }
      if (response.contentLength > limit) {
        throw const DnsResponseTooLargeException('DNS body exceeds limit');
      }
      final bytes = BytesBuilder(copy: false);
      await for (final chunk in response) {
        if (bytes.length + chunk.length > limit) {
          throw const DnsResponseTooLargeException('DNS body exceeds limit');
        }
        bytes.add(chunk);
        if (_done) return;
      }
      final body = bytes.takeBytes();
      if (query != null) validateDnsWireResponse(query!, body);
      _finish(DohHttpResponse(response.statusCode, body,
          age: _age(response.headers[HttpHeaders.ageHeader])));
    } catch (error, stack) {
      _finish(
          error is DnsException
              ? error
              : const DnsTransportException('Resolver connection failed'),
          stack);
    }
  }
}
