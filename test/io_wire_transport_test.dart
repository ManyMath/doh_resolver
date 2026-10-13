import 'dart:async';
import 'dart:io';

import 'package:doh_resolver/doh_resolver_io.dart';
import 'package:test/test.dart';

import 'support/dns_wire.dart';
import 'support/test_pki.dart';
import 'support/tunnel_proxy.dart';

void main() {
  late HttpServer server;
  late TestPki pki;
  setUpAll(() => pki = TestPki.generate());
  setUp(() async => server = await HttpServer.bindSecure(
      InternetAddress.loopbackIPv4, 0, pki.serverContext()));
  tearDown(() => server.close(force: true));
  Uri endpoint() => Uri.parse('https://localhost:${server.port}/dns-query');

  void serve(
      {int status = 200,
      String type = 'application/dns-message',
      List<int> Function(List<int> query)? reply,
      void Function(HttpRequest request, List<int> body)? inspect}) {
    server.listen((request) async {
      final body = await request.fold<List<int>>([], (a, b) => a..addAll(b));
      inspect?.call(request, body);
      request.response
        ..statusCode = status
        ..headers.contentType = ContentType.parse(type)
        ..add((reply ?? (q) => wireReply(id: q[0] << 8 | q[1]))(body));
      await request.response.close();
    });
  }

  for (final proxied in [false, true]) {
    test('padded RFC 8484 POST over ${proxied ? 'SOCKS' : 'direct'} HTTPS',
        () async {
      List<int>? sent;
      serve(inspect: (request, body) {
        expect(request.method, 'POST');
        expect(
            request.headers.contentType?.mimeType, 'application/dns-message');
        expect(request.headers.value('accept'), 'application/dns-message');
        sent = body;
      });
      final proxy = TunnelProxy(upstreamPort: server.port);
      if (proxied) {
        await proxy.start();
        addTearDown(proxy.close);
      }
      final transport = IoDohTransport(
          securityContext: pki.clientContext(),
          proxy: proxied
              ? SocksProxy(InternetAddress.loopbackIPv4, proxy.port)
              : null);
      final query = wireQuery(id: 0xbeef);
      final response = await transport
          .startWire(endpoint(), query, maxResponseBytes: 65535)
          .result;
      expect(response.statusCode, 200);
      expect(response.body.sublist(0, 2), [0xbe, 0xef]);
      expect(sent!.length % 128, 0);
      expect(sent!.sublist(2, query.length - 2),
          query.sublist(2, query.length - 2),
          reason: 'only the ID and OPT length may change');
      if (proxied) {
        expect(proxy.targetType, 3, reason: 'hostname must reach the proxy');
        expect(proxy.target, 'localhost');
      }
    });
  }

  test('padding can be disabled', () async {
    List<int>? sent;
    serve(inspect: (_, body) => sent = body);
    final query = wireQuery();
    await IoDohTransport(
            securityContext: pki.clientContext(), padQueries: false)
        .startWire(endpoint(), query, maxResponseBytes: 65535)
        .result;
    expect(sent!.sublist(2), query.sublist(2));
  });

  test('rejects invalid queries and URIs through the result, unconnected',
      () async {
    var requests = 0;
    server.listen((_) => requests++);
    final transport = IoDohTransport(securityContext: pki.clientContext());
    for (final query in [
      <int>[],
      wireReply(),
      [...wireQuery(), 0]
    ]) {
      await expectLater(
          transport.startWire(endpoint(), query, maxResponseBytes: 512).result,
          throwsA(isA<DnsInvalidQueryException>()));
    }
    for (final uri in [
      endpoint().replace(scheme: 'http'),
      endpoint().replace(userInfo: 'user'),
      endpoint().replace(fragment: 'x'),
    ]) {
      await expectLater(
          transport.startWire(uri, wireQuery(), maxResponseBytes: 512).result,
          throwsA(isA<DnsInvalidQueryException>()));
      await expectLater(transport.start(uri, maxResponseBytes: 512).result,
          throwsA(isA<DnsInvalidQueryException>()));
    }
    await expectLater(
        transport
            .startWire(endpoint(), wireQuery(), maxResponseBytes: 0)
            .result,
        throwsA(isA<DnsInvalidQueryException>()));
    expect(requests, 0);
  });

  for (final (name, code, status, type, reply) in [
    (
      'mismatched ID',
      isA<DnsQuestionMismatchException>(),
      200,
      'application/dns-message',
      (List<int> q) => wireReply(id: (q[0] << 8 | q[1]) ^ 1)
    ),
    (
      'another question',
      isA<DnsQuestionMismatchException>(),
      200,
      'application/dns-message',
      (List<int> q) => wireReply(name: 'b.example', id: q[0] << 8 | q[1])
    ),
    (
      'truncated reply',
      isA<DnsMalformedResponseException>(),
      200,
      'application/dns-message',
      (List<int> q) => wireReply(id: q[0] << 8 | q[1], flags: 0x8380)
    ),
    (
      'JSON content type',
      isA<DnsMalformedResponseException>(),
      200,
      'application/json',
      (List<int> q) => wireReply(id: q[0] << 8 | q[1])
    ),
    (
      'server error',
      isA<DnsTransportException>(),
      500,
      'application/dns-message',
      (List<int> q) => wireReply(id: q[0] << 8 | q[1])
    ),
  ]) {
    test('rejects $name', () async {
      serve(status: status, type: type, reply: reply);
      await expectLater(
          IoDohTransport(securityContext: pki.clientContext())
              .startWire(endpoint(), wireQuery(), maxResponseBytes: 65535)
              .result,
          throwsA(code));
    });
  }

  for (final proxied in [false, true]) {
    test(
        'request deadline tears down a ${proxied ? 'proxied' : 'direct'} '
        'stalled exchange', () async {
      final arrived = Completer<void>();
      server.listen((request) {
        if (!arrived.isCompleted) arrived.complete();
      });
      final proxy = TunnelProxy(upstreamPort: server.port);
      if (proxied) {
        await proxy.start();
        addTearDown(proxy.close);
      }
      final transport = IoDohTransport(
          securityContext: pki.clientContext(),
          requestTimeout: const Duration(milliseconds: 300),
          proxy: proxied
              ? SocksProxy(InternetAddress.loopbackIPv4, proxy.port)
              : null);
      await expectLater(
          transport
              .startWire(endpoint(), wireQuery(), maxResponseBytes: 512)
              .result,
          throwsA(isA<DnsTimeoutException>()));
      expect(arrived.isCompleted, isTrue);
      if (proxied) {
        await proxy.disconnected.future.timeout(const Duration(seconds: 2));
      }
    });
  }

  test('concurrency limit queues requests and frees slots on every outcome',
      () async {
    // Concurrent handshakes race and the wire ID is the transport's, so key
    // held requests by question name.
    final held = <String, (HttpRequest, List<int>)>{};
    var arrivals = 0;
    server.listen((request) async {
      final body = await request.fold<List<int>>([], (a, b) => a..addAll(b));
      held[wireFirstLabel(body)] = (request, body);
      arrivals++;
    });
    Future<void> until(bool Function() condition) async {
      for (var i = 0; i < 200 && !condition(); i++) {
        await Future<void>.delayed(const Duration(milliseconds: 10));
      }
      expect(condition(), isTrue);
    }

    final transport = IoDohTransport(
        securityContext: pki.clientContext(),
        maxConcurrentRequests: 2,
        requestTimeout: const Duration(seconds: 5));
    final operations = [
      for (var id = 1; id <= 4; id++)
        transport.startWire(endpoint(), wireQuery(id: id, name: 'q$id.example'),
            maxResponseBytes: 512)
    ];
    final outcomes = [
      for (final operation in operations)
        operation.result.then<Object>((r) => r, onError: (Object e) => e)
    ];
    await until(() => arrivals == 2);
    operations[3].cancel();
    expect(await outcomes[3], isA<DnsCancelledException>());
    operations[0].cancel();
    expect(await outcomes[0], isA<DnsCancelledException>());
    await until(() => arrivals == 3);
    expect(held.keys, unorderedEquals(['q1', 'q2', 'q3']));
    for (final label in ['q2', 'q3']) {
      final (request, body) = held[label]!;
      request.response
        ..headers.contentType = ContentType('application', 'dns-message')
        ..add(wireEcho(body));
      unawaited(request.response.close());
    }
    expect(await outcomes[1], isA<DohHttpResponse>());
    expect(await outcomes[2], isA<DohHttpResponse>());
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(arrivals, 3);
  });

  test('the waiting queue rejects excess work and cancellation frees space',
      () async {
    final held = <HttpRequest>[];
    server.listen(held.add);
    Future<void> until(bool Function() condition) async {
      for (var i = 0; i < 200 && !condition(); i++) {
        await Future<void>.delayed(const Duration(milliseconds: 10));
      }
      expect(condition(), isTrue);
    }

    Future<void> answer(HttpRequest request) async {
      final body = await request.fold<List<int>>([], (a, b) => a..addAll(b));
      request.response
        ..headers.contentType = ContentType('application', 'dns-message')
        ..add(wireReply(id: body[0] << 8 | body[1]));
      await request.response.close();
    }

    final transport = IoDohTransport(
        securityContext: pki.clientContext(),
        maxConcurrentRequests: 1,
        maxQueuedRequests: 2);
    final active = transport.startWire(endpoint(), wireQuery(id: 1),
        maxResponseBytes: 512);
    final cancelled = transport.startWire(endpoint(), wireQuery(id: 2),
        maxResponseBytes: 512);
    final queued = transport.startWire(endpoint(), wireQuery(id: 3),
        maxResponseBytes: 512);
    await expectLater(
        transport
            .startWire(endpoint(), wireQuery(id: 4), maxResponseBytes: 512)
            .result,
        throwsA(isA<DnsTransportException>()));
    final cancelledResult =
        expectLater(cancelled.result, throwsA(isA<DnsCancelledException>()));
    cancelled.cancel();
    await cancelledResult;
    final replacement = transport.startWire(endpoint(), wireQuery(id: 5),
        maxResponseBytes: 512);

    await until(() => held.length == 1);
    await answer(held[0]);
    expect((await active.result).body.sublist(0, 2), u16(1));
    await until(() => held.length == 2);
    await answer(held[1]);
    expect((await queued.result).body.sublist(0, 2), u16(3));
    await until(() => held.length == 3);
    await answer(held[2]);
    expect((await replacement.result).body.sublist(0, 2), u16(5));
    expect(held, hasLength(3));
  });
}
