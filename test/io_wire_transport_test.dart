import 'dart:async';
import 'dart:io';

import 'package:doh_resolver/doh_resolver_io.dart';
import 'package:test/test.dart';

import 'dns_test.dart' show error;
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
      expect(sent!.sublist(0, query.length - 2),
          query.sublist(0, query.length - 2));
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
    expect(sent, query);
  });

  test('rejects invalid wire queries before connecting', () {
    final transport = IoDohTransport(securityContext: pki.clientContext());
    for (final query in [
      <int>[],
      wireReply(),
      [...wireQuery(), 0]
    ]) {
      expect(
          () => transport.startWire(endpoint(), query, maxResponseBytes: 512),
          throwsArgumentError);
    }
  });

  for (final (name, code, status, type, reply) in [
    (
      'mismatched ID',
      DnsError.questionMismatch,
      200,
      'application/dns-message',
      (List<int> q) => wireReply(id: (q[0] << 8 | q[1]) ^ 1)
    ),
    (
      'another question',
      DnsError.questionMismatch,
      200,
      'application/dns-message',
      (List<int> q) => wireReply(name: 'b.example', id: q[0] << 8 | q[1])
    ),
    (
      'truncated reply',
      DnsError.malformedResponse,
      200,
      'application/dns-message',
      (List<int> q) => wireReply(id: q[0] << 8 | q[1], flags: 0x8380)
    ),
    (
      'JSON content type',
      DnsError.malformedResponse,
      200,
      'application/json',
      (List<int> q) => wireReply(id: q[0] << 8 | q[1])
    ),
    (
      'server error',
      DnsError.transport,
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
          throwsA(error(code)));
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
          throwsA(error(DnsError.timedOut)));
      expect(arrived.isCompleted, isTrue);
      if (proxied) {
        await proxy.disconnected.future.timeout(const Duration(seconds: 2));
      }
    });
  }

  test('concurrency limit queues requests and frees slots on every outcome',
      () async {
    final held = <HttpRequest>[];
    var arrivals = 0;
    server.listen((request) {
      arrivals++;
      held.add(request);
    });
    Future<void> until(bool Function() condition) async {
      for (var i = 0; i < 200 && !condition(); i++) {
        await Future<void>.delayed(const Duration(milliseconds: 10));
      }
      expect(condition(), isTrue);
    }

    final transport = IoDohTransport(
        securityContext: pki.clientContext(), maxConcurrentRequests: 2);
    final operations = [
      for (var id = 1; id <= 4; id++)
        transport.startWire(endpoint(), wireQuery(id: id),
            maxResponseBytes: 512)
    ];
    final outcomes = [
      for (final operation in operations)
        operation.result.then<Object>((r) => r, onError: (Object e) => e)
    ];
    await until(() => arrivals == 2);
    operations[3].cancel();
    expect(await outcomes[3], error(DnsError.cancelled));
    operations[0].cancel();
    expect(await outcomes[0], error(DnsError.cancelled));
    await until(() => arrivals == 3);
    for (final request in held.skip(1)) {
      final body = await request.fold<List<int>>([], (a, b) => a..addAll(b));
      request.response
        ..headers.contentType = ContentType('application', 'dns-message')
        ..add(wireReply(id: body[0] << 8 | body[1]));
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
        throwsA(error(DnsError.transport)));
    final cancelledResult =
        expectLater(cancelled.result, throwsA(error(DnsError.cancelled)));
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
