import 'dart:async';
import 'dart:collection';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:socks_socket/socks_connection.dart';
import 'dns.dart';
import 'resolver.dart';
import 'wire.dart';

/// A SOCKS5 proxy, addressed numerically so no local DNS lookup is needed.
/// Use [SocksCredentials.isolation] for Tor stream isolation.
class SocksProxy {
  final InternetAddress host;
  final int port;
  final SocksCredentials? credentials;
  const SocksProxy(this.host, this.port, {this.credentials});
}

/// A `dart:io` HTTPS/1.1 DoH transport, direct or through SOCKS5.
///
/// It verifies the endpoint certificate, never follows redirects, never falls
/// back from a configured proxy to a direct connection, bounds bodies and
/// deadlines, and admits at most [maxConcurrentRequests] running plus
/// [maxQueuedRequests] waiting operations. Call [close] when done.
class IoDohTransport implements DohTransport, DohWireTransport {
  final SocksProxy? proxy;

  /// Sends every proxied request to this address instead of letting the proxy
  /// resolve the endpoint host. It applies to all endpoints used with this
  /// transport; TLS still verifies the requested host name.
  final InternetAddress? proxyDestination;
  final SecurityContext? securityContext;
  final Duration connectionTimeout;

  /// The deadline for each operation, including time spent queued.
  final Duration requestTimeout;
  final Duration idleTimeout;
  final int maxConcurrentRequests;
  final int maxQueuedRequests;

  /// Whether wire queries are padded with [padDnsWireQuery].
  final bool padQueries;

  /// Whether wire queries to the same origin share connections. Defaults to
  /// off with a [proxy]: a shared connection lets the resolver link lookups
  /// that would otherwise travel over separate (for example Tor) streams.
  /// The transport rewrites each wire ID to keep it unique on a connection
  /// and restores the caller's ID in the response, except for SIG(0)- or
  /// TSIG-signed queries and `preserveMessage` exchanges, whose IDs are kept
  /// and still never repeat on a connection. JSON requests never share
  /// connections.
  final bool reuseConnections;
  int _active = 0;
  bool _closed = false;
  final _waiting = Queue<_IoRequest>();
  final _running = <_IoRequest>{};
  final _idle = <_Lane>[];
  // Lanes fork from here: forking from Zone.current during a queued handoff
  // would parent each new lane on its predecessor and keep the chain alive.
  final _zone = Zone.current;
  final _random = Random.secure();
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
      bool? reuseConnections})
      : reuseConnections = reuseConnections ?? proxy == null {
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
      {required int maxResponseBytes, bool preserveMessage = false}) {
    final List<int> checked;
    final bool preserved;
    try {
      // SIG(0) and TSIG sign the header, so signed queries are always kept.
      preserved = preserveMessage || isSignedDnsWireQuery(query);
      checked = padQueries && !preserved
          ? padDnsWireQuery(query)
          : checkedDnsWireQuery(query);
    } on DnsException catch (error) {
      return DnsOperation.failed(error);
    }
    return _start(uri, min(maxResponseBytes, 65535), checked, preserved);
  }

  /// Fails queued and running operations with [DnsCancelledException], fails
  /// later starts the same way, and begins closing every connection. Socket
  /// teardown finishes asynchronously after this returns.
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
      [List<int>? query, bool preserved = false]) {
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
    final request = _IoRequest(this, uri, maxResponseBytes, query, preserved);
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
      final callerId = query[0] << 8 | query[1];
      for (var i = _idle.length - 1; i >= 0; i--) {
        final candidate = _idle[i];
        if (candidate.origin == origin &&
            (request.preserved
                ? candidate.canClaim(callerId)
                : candidate.hasFreeWireIds)) {
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
    if (request.query case final query?) {
      // The transport owns the ID on the wire. Callers may all send ID 0 as
      // RFC 8484 recommends, yet a stale reply on a reused connection still
      // fails the ID check instead of answering the next request. Preserved
      // queries keep their ID, which is still never repeated on a connection,
      // and their response is returned exactly as received.
      final callerId = query[0] << 8 | query[1];
      if (request.preserved) {
        lane.claimWireId(_random, callerId);
        request.sent = query;
      } else {
        final id = lane.claimWireId(_random);
        request.sent = Uint8List.fromList(query)
          ..[0] = id >> 8
          ..[1] = id & 0xff;
      }
    }
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
  var _usedWireIdCount = 0;
  _IoRequest? owner;
  bool retired = false;

  _Lane(this.origin);

  // Retiring at half the ID space keeps random selection to ~2 draws.
  bool get hasFreeWireIds => _usedWireIdCount < 32768;

  bool canClaim(int id) => hasFreeWireIds && !_isUsed(id);

  bool _isUsed(int id) => _usedWireIds[id >> 3] & (1 << (id & 7)) != 0;

  /// Claims [id], or a random unused ID when none is given.
  int claimWireId(Random random, [int? id]) {
    id ??= () {
      while (true) {
        final candidate = random.nextInt(65536);
        if (!_isUsed(candidate)) return candidate;
      }
    }();
    assert(!_isUsed(id));
    _usedWireIds[id >> 3] |= 1 << (id & 7);
    _usedWireIdCount++;
    return id;
  }
}

class _IoRequest {
  final IoDohTransport transport;
  final Uri uri;
  final int limit;
  final List<int>? query;
  List<int>? sent;
  final bool preserved;
  final result = Completer<DohHttpResponse>();
  _Lane? lane;
  late final Timer _deadline;
  bool _done = false;
  _IoRequest(this.transport, this.uri, this.limit, this.query, this.preserved) {
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
      if (sent case final sent?) {
        request.headers.contentType = ContentType('application', 'dns-message');
        request.contentLength = sent.length;
        request.add(sent);
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
      if (sent case final sent?) {
        validateDnsWireResponse(sent, body);
        body
          ..[0] = query![0]
          ..[1] = query![1];
      }
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
