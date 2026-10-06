import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:doh_resolver/doh_resolver_io.dart';
import 'package:test/test.dart';
import 'dns_test.dart' show reply, error;
import 'support/test_pki.dart';
import 'support/tunnel_proxy.dart';

void main() {
  late HttpServer server;
  late SecurityContext trust;
  late TestPki pki;
  setUpAll(() => pki = TestPki.generate());
  setUp(() async {
    trust = pki.clientContext();
    server = await HttpServer.bindSecure(
        InternetAddress.loopbackIPv4, 0, pki.serverContext());
  });
  tearDown(() => server.close(force: true));
  Uri endpoint() => Uri.parse('https://localhost:${server.port}/resolve');

  for (final proxied in [false, true]) {
    test('authenticated TXT over ${proxied ? 'SOCKS' : 'direct'} HTTPS',
        () async {
      var requests = 0;
      server.listen((request) {
        requests++;
        expect(request.uri.queryParameters['name'], 'alice.example.');
        expect(request.uri.queryParameters['do'], 'true');
        expect(request.uri.queryParameters['cd'], 'false');
        expect(request.uri.queryParameters['edns_client_subnet'], '0.0.0.0/0');
        expect(request.headers.value('accept'), 'application/dns-json');
        request.response.headers.contentType = ContentType.json;
        request.response.write(jsonEncode(reply()));
        request.response.close();
      });
      final proxy = TunnelProxy(upstreamPort: server.port, fragmented: true);
      if (proxied) {
        await proxy.start();
        addTearDown(proxy.close);
      }
      final resolver = DohResolver(
          endpoint: endpoint(),
          transport: IoDohTransport(
              securityContext: trust,
              proxy: proxied
                  ? SocksProxy(InternetAddress.loopbackIPv4, proxy.port)
                  : null,
              proxyDestination: proxied ? InternetAddress('8.8.8.8') : null));
      final result = await resolver.lookupTxt('alice.example');
      expect(result.records.single.text, 'oa1:xmr recipient_address=valid;');
      expect(result.resolver, endpoint());
      expect(requests, 1);
      if (proxied) {
        expect(proxy.target, '8.8.8.8');
        await proxy.disconnected.future.timeout(const Duration(seconds: 2));
      }
    });
  }
  test('a rejected required proxy never falls back to reachable direct HTTPS',
      () async {
    var requests = 0;
    server.listen((request) {
      requests++;
      request.response.close();
    });
    final proxy = TunnelProxy(replyCode: 5);
    await proxy.start();
    addTearDown(proxy.close);
    final resolver = DohResolver(
        endpoint: endpoint(),
        transport: IoDohTransport(
            securityContext: trust,
            proxy: SocksProxy(InternetAddress.loopbackIPv4, proxy.port)));
    await expectLater(resolver.lookupTxt('alice.example'),
        throwsA(error(DnsError.transport)));
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(requests, 0);
    expect(proxy.connections, 1);
  });
  test('HTTPS identity must be trusted', () async {
    server.listen((r) => r.response.close(), onError: (Object _) {});
    await expectLater(
        DohResolver(endpoint: endpoint(), transport: IoDohTransport())
            .lookupTxt('alice.example'),
        throwsA(error(DnsError.transport)));
  });
  test('redirects never produce a second request', () async {
    var requests = 0;
    server.listen((r) {
      requests++;
      r.response.statusCode = 302;
      r.response.headers
          .set('location', endpoint().replace(path: '/redirected').toString());
      r.response.close();
    });
    await expectLater(
        DohResolver(
                endpoint: endpoint(),
                transport: IoDohTransport(securityContext: trust))
            .lookupTxt('alice.example'),
        throwsA(error(DnsError.transport)));
    expect(requests, 1);
  });
  test('streaming response size limit aborts before parsing', () async {
    server.listen((r) {
      r.response.headers.contentType = ContentType.json;
      r.response.write('x' * 129);
      r.response.close();
    });
    await expectLater(
        DohResolver(
                endpoint: endpoint(),
                maxResponseBytes: 128,
                transport: IoDohTransport(securityContext: trust))
            .lookupTxt('alice.example'),
        throwsA(error(DnsError.responseTooLarge)));
  });
  test('unsigned response is not accepted merely because HTTPS succeeded',
      () async {
    server.listen((r) {
      r.response.headers.contentType = ContentType.json;
      r.response.write(jsonEncode(reply()..['AD'] = false));
      r.response.close();
    });
    await expectLater(
        DohResolver(
                endpoint: endpoint(),
                transport: IoDohTransport(securityContext: trust))
            .lookupTxt('alice.example'),
        throwsA(error(DnsError.authenticationUnavailable)));
  });
  for (final cancel in [false, true]) {
    test('${cancel ? 'cancel' : 'timeout'} destroys stalled response transport',
        () async {
      final sent = Completer<void>();
      server.listen((r) async {
        r.response.headers.contentType = ContentType.json;
        r.response.write('{');
        await r.response.flush();
        if (!sent.isCompleted) sent.complete();
      });
      final proxy = TunnelProxy(upstreamPort: server.port);
      await proxy.start();
      addTearDown(proxy.close);
      final resolver = DohResolver(
          endpoint: endpoint(),
          timeout: const Duration(milliseconds: 300),
          transport: IoDohTransport(
              securityContext: trust,
              proxy: SocksProxy(InternetAddress.loopbackIPv4, proxy.port)));
      final operation = resolver.startTxtLookup('alice.example');
      final failed = expectLater(operation.result,
          throwsA(error(cancel ? DnsError.cancelled : DnsError.timedOut)));
      await sent.future;
      if (cancel) operation.cancel();
      await failed;
      await proxy.disconnected.future.timeout(const Duration(seconds: 2));
    });
  }
  test('generated test certificate is a short-lived serverAuth leaf', () async {
    server.listen((r) => r.response.close());
    final socket =
        await SecureSocket.connect('localhost', server.port, context: trust);
    final leaf = socket.peerCertificate!;
    socket.destroy();
    final now = DateTime.now();
    expect(leaf.issuer, contains('doh_resolver test CA'));
    expect(leaf.subject, isNot(leaf.issuer));
    expect(leaf.startValidity.isBefore(now), isTrue);
    expect(leaf.endValidity.difference(leaf.startValidity).inDays,
        lessThanOrEqualTo(31));
    await expectLater(
        SecureSocket.connect('localhost', server.port,
            context: TestPki.generate().clientContext()),
        throwsA(isA<HandshakeException>()));
  });
  test('requests identity encoding without a client fingerprint', () async {
    server.listen((r) {
      expect(r.headers[HttpHeaders.acceptEncodingHeader], isNull);
      expect(r.headers[HttpHeaders.userAgentHeader], isNull);
      r.response.headers.contentType = ContentType.json;
      r.response.write(jsonEncode(reply()));
      r.response.close();
    });
    final result = await DohResolver(
            endpoint: endpoint(),
            transport: IoDohTransport(securityContext: trust))
        .lookupTxt('alice.example');
    expect(result.records, hasLength(1));
  });
  for (final (type, encoding) in [
    (null, null),
    (ContentType.text, null),
    (ContentType.html, null),
    (ContentType.json, 'gzip'),
  ]) {
    test('rejects JSON body typed $type encoded $encoding', () async {
      server.listen((r) {
        if (type != null) r.response.headers.contentType = type;
        if (encoding != null) {
          r.response.headers.set(HttpHeaders.contentEncodingHeader, encoding);
        }
        r.response.write(jsonEncode(reply()));
        r.response.close();
      });
      await expectLater(
          DohResolver(
                  endpoint: endpoint(),
                  transport: IoDohTransport(securityContext: trust))
              .lookupTxt('alice.example'),
          throwsA(error(DnsError.malformedResponse)));
    });
  }
}
