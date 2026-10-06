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
  final int maxConcurrentRequests;
  final int maxQueuedRequests;
  final bool padQueries;
  int _active = 0;
  final _waiting = Queue<_IoRequest>();
  IoDohTransport(
      {this.proxy,
      this.proxyDestination,
      this.securityContext,
      this.connectionTimeout = const Duration(seconds: 5),
      this.requestTimeout = const Duration(seconds: 30),
      this.maxConcurrentRequests = 8,
      this.maxQueuedRequests = 64,
      this.padQueries = true}) {
    if (proxy == null && proxyDestination != null) {
      throw ArgumentError('proxyDestination requires an explicit proxy');
    }
    if (connectionTimeout <= Duration.zero ||
        requestTimeout <= Duration.zero ||
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
    return _start(uri, min(maxResponseBytes, 65535),
        padQueries ? padDnsWireQuery(query) : checkedDnsWireQuery(query));
  }

  DnsOperation<DohHttpResponse> _start(Uri uri, int maxResponseBytes,
      [List<int>? query]) {
    if (uri.scheme != 'https' ||
        uri.host.isEmpty ||
        uri.userInfo.isNotEmpty ||
        uri.hasFragment ||
        maxResponseBytes < 1) {
      throw ArgumentError('Expected a bounded HTTPS request');
    }
    if (_active >= maxConcurrentRequests &&
        _waiting.length >= maxQueuedRequests) {
      return DnsOperation(
          Future.error(const DnsException(
              DnsError.transport, 'DNS transport request queue is full')),
          () {});
    }
    final request = _IoRequest(this, uri, maxResponseBytes, query);
    if (_active < maxConcurrentRequests) {
      _active++;
      request.run();
    } else {
      _waiting.add(request);
    }
    return DnsOperation(request.result.future, request.cancel);
  }

  void _release(_IoRequest request) {
    if (_waiting.remove(request)) return;
    _active--;
    while (_waiting.isNotEmpty && _active < maxConcurrentRequests) {
      _active++;
      _waiting.removeFirst().run();
    }
  }
}

class _IoRequest {
  final IoDohTransport transport;
  final Uri uri;
  final int limit;
  final List<int>? query;
  final result = Completer<DohHttpResponse>();
  final _tasks = <ConnectionTask<Socket>>[];
  HttpClient? _client;
  late final Timer _deadline;
  bool _done = false;
  _IoRequest(this.transport, this.uri, this.limit, this.query) {
    _deadline = Timer(
        transport.requestTimeout,
        () => _finish(
            const DnsException(DnsError.timedOut, 'DNS request timed out')));
  }

  HttpClient _connect() {
    final client = _client = HttpClient(context: transport.securityContext)
      ..connectionTimeout = transport.connectionTimeout
      ..autoUncompress = false
      ..userAgent = null
      ..findProxy = (_) => 'DIRECT';
    final proxy = transport.proxy;
    if (proxy != null) {
      client.connectionFactory = (destination, _, __) async {
        if (_done ||
            destination.scheme != uri.scheme ||
            destination.host != uri.host ||
            destination.port != uri.port) {
          throw const DnsException(
              DnsError.cancelled, 'DNS connection cancelled or redirected');
        }
        final task = SocksConnection.start(
            proxyHost: proxy.host,
            proxyPort: proxy.port,
            targetHost: transport.proxyDestination?.address ?? uri.host,
            targetPort: uri.port,
            tlsHost: uri.host,
            securityContext: transport.securityContext,
            credentials: proxy.credentials,
            timeout: transport.connectionTimeout);
        _tasks.add(task);
        return task;
      };
    }
    return client;
  }

  void _finish(Object outcome, [StackTrace? stack]) {
    if (_done) return;
    _done = true;
    _deadline.cancel();
    if (outcome is DohHttpResponse) {
      result.complete(outcome);
    } else {
      result.completeError(outcome, stack);
    }
    _client?.close(force: true);
    for (final task in _tasks) {
      task.cancel();
    }
    _tasks.clear();
    transport._release(this);
  }

  void cancel() =>
      _finish(const DnsException(DnsError.cancelled, 'DNS request cancelled'));

  Future<void> run() async {
    if (_done) return;
    try {
      final request =
          await _connect().openUrl(query == null ? 'GET' : 'POST', uri);
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
        throw DnsException(DnsError.transport, 'Resolver HTTP request failed',
            responseCode: response.statusCode);
      }
      final mime = response.headers.contentType?.mimeType;
      if (query == null
          ? mime != 'application/json' && mime != 'application/dns-json'
          : mime != 'application/dns-message') {
        throw const DnsException(
            DnsError.malformedResponse, 'Unexpected DNS response media type');
      }
      if (response.headers.value(HttpHeaders.contentEncodingHeader)
          case final encoding? when encoding.toLowerCase() != 'identity') {
        throw const DnsException(
            DnsError.malformedResponse, 'Encoded DNS response');
      }
      if (response.contentLength > limit) {
        throw const DnsException(
            DnsError.responseTooLarge, 'DNS body exceeds limit');
      }
      final bytes = BytesBuilder(copy: false);
      await for (final chunk in response) {
        if (bytes.length + chunk.length > limit) {
          throw const DnsException(
              DnsError.responseTooLarge, 'DNS body exceeds limit');
        }
        bytes.add(chunk);
        if (_done) return;
      }
      final body = bytes.takeBytes();
      if (query != null) validateDnsWireResponse(query!, body);
      _finish(DohHttpResponse(response.statusCode, body));
    } catch (error, stack) {
      _finish(
          error is DnsException
              ? error
              : const DnsException(
                  DnsError.transport, 'Resolver connection failed'),
          stack);
    }
  }
}
