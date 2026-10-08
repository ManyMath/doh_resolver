import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:doh_resolver/doh_resolver_io.dart';
import 'package:test/test.dart';

import 'dns_test.dart' show error;
import 'support/dns_wire.dart';
import 'support/scripted_server.dart';
import 'support/test_pki.dart';
import 'support/tunnel_proxy.dart';

void main() {
  late TestPki pki;
  late ScriptedServer server;
  setUpAll(() => pki = TestPki.generate());
  tearDown(() => server.close());

  Future<void> serve(FutureOr<void> Function(ScriptedExchange) handler) async {
    server = ScriptedServer(pki.serverContext(), handler);
    await server.start();
  }

  void answer(ScriptedExchange e) => e.send(httpResponse(wireReply(id: e.id)));

  Future<TunnelProxy?> tunnel(bool proxied) async {
    if (!proxied) return null;
    final proxy = TunnelProxy(upstreamPort: server.port);
    await proxy.start();
    addTearDown(proxy.close);
    return proxy;
  }

  IoDohTransport transport(TunnelProxy? proxy,
      {bool reuseConnections = true,
      int maxConcurrentRequests = 8,
      Duration requestTimeout = const Duration(seconds: 3),
      Duration idleTimeout = const Duration(seconds: 5)}) {
    final transport = IoDohTransport(
        securityContext: pki.clientContext(),
        proxy: proxy == null
            ? null
            : SocksProxy(InternetAddress.loopbackIPv4, proxy.port,
                credentials: SocksCredentials.isolation('lookup')),
        reuseConnections: reuseConnections,
        maxConcurrentRequests: maxConcurrentRequests,
        requestTimeout: requestTimeout,
        idleTimeout: idleTimeout);
    addTearDown(transport.close);
    return transport;
  }

  DnsOperation<DohHttpResponse> start(IoDohTransport transport, int id) =>
      transport.startWire(
          Uri.parse('https://localhost:${server.port}/dns-query'),
          wireQuery(id: id),
          maxResponseBytes: 512);

  Future<void> until(bool Function() condition) async {
    for (var i = 0; i < 300 && !condition(); i++) {
      await Future<void>.delayed(const Duration(milliseconds: 10));
    }
    expect(condition(), isTrue);
  }

  Future<void> expectAnswer(IoDohTransport transport, int id) async {
    final response = await start(transport, id).result;
    expect(response.body.sublist(0, 2), u16(id));
  }

  for (final proxied in [false, true]) {
    final mode = proxied ? 'SOCKS' : 'direct';
    for (final reuse in [true, false]) {
      test(
          'sequential $mode requests open ${reuse ? 'one connection' : 'one '
              'connection each'} with reuse ${reuse ? 'on' : 'off'}', () async {
        await serve(answer);
        final proxy = await tunnel(proxied);
        final t = transport(proxy, reuseConnections: reuse);
        for (var id = 1; id <= 4; id++) {
          await expectAnswer(t, id);
        }
        expect(server.connections, reuse ? 1 : 4);
        if (proxy != null) {
          expect(proxy.connections, reuse ? 1 : 4);
          expect(proxy.username, 'lookup');
          expect(proxy.targetType, 3);
          expect(proxy.target, 'localhost');
        }
      });
    }

    for (final (
          name,
          code,
          cancel,
          Future<void> Function(ScriptedExchange, Completer<void>) first
        ) in [
      (
        'an empty-body 404',
        DnsError.transport,
        false,
        (ScriptedExchange e, Completer<void> _) async =>
            e.send(httpResponse([], status: 404))
      ),
      (
        'a JSON-typed reply',
        DnsError.malformedResponse,
        false,
        (ScriptedExchange e, Completer<void> _) async =>
            e.send(httpResponse(wireReply(id: e.id), type: 'application/json'))
      ),
      (
        'a buffered reply with another ID',
        DnsError.questionMismatch,
        false,
        (ScriptedExchange e, Completer<void> _) async =>
            e.send(httpResponse(wireReply(id: e.id ^ 1)))
      ),
      (
        'a chunked reply with another ID',
        DnsError.questionMismatch,
        false,
        (ScriptedExchange e, Completer<void> _) async =>
            e.send(httpResponse(wireReply(id: e.id ^ 1), chunked: true))
      ),
      (
        'a chunked reply over the size limit',
        DnsError.responseTooLarge,
        false,
        (ScriptedExchange e, Completer<void> _) async =>
            e.send(httpResponse(List.filled(600, 0), chunked: true))
      ),
      (
        'a timed-out exchange answered late with an extra response',
        DnsError.timedOut,
        false,
        (ScriptedExchange e, Completer<void> _) async {
          await Future<void>.delayed(const Duration(milliseconds: 500));
          answer(e);
          answer(e);
        }
      ),
      (
        'a cancelled exchange answered late with an extra response',
        DnsError.cancelled,
        true,
        (ScriptedExchange e, Completer<void> ready) async {
          ready.complete();
          await Future<void>.delayed(const Duration(milliseconds: 100));
          answer(e);
          answer(e);
        }
      ),
      (
        'a reply cancelled mid-body and then completed with an extra response',
        DnsError.cancelled,
        true,
        (ScriptedExchange e, Completer<void> ready) async {
          final reply = httpResponse(wireReply(id: e.id));
          e.send(reply.sublist(0, reply.length - 4));
          await e.socket.flush();
          ready.complete();
          await Future<void>.delayed(const Duration(milliseconds: 100));
          e.send(reply.sublist(reply.length - 4));
          answer(e);
        }
      ),
    ]) {
      test('$mode: $name never reaches the next request', () async {
        final ready = Completer<void>();
        await serve((e) => e.index == 1 ? first(e, ready) : answer(e));
        final proxy = await tunnel(proxied);
        final t =
            transport(proxy, requestTimeout: const Duration(milliseconds: 300));
        final operation = start(t, 0x1111);
        final failed = expectLater(operation.result, throwsA(error(code)));
        if (cancel) {
          await ready.future;
          operation.cancel();
        }
        await failed;
        await until(() => server.closed == 1);
        await Future<void>.delayed(const Duration(milliseconds: 300));
        await expectAnswer(t, 0x4242);
        expect(server.connections, 2);
        expect(server.exchanges.last.connection, 2);
        if (proxy != null) expect(proxy.connections, 2);
      });
    }

    test('$mode: cancelling one request leaves other lanes untouched',
        () async {
      await serve((e) {
        if (e.index > 2) answer(e);
      });
      final proxy = await tunnel(proxied);
      final t = transport(proxy, maxConcurrentRequests: 2);
      final a = start(t, 1);
      final b = start(t, 2);
      final aFailed = expectLater(a.result, throwsA(error(DnsError.cancelled)));
      await until(() => server.exchanges.length == 2);
      final held = server.exchanges.firstWhere((e) => e.id == 2);
      a.cancel();
      await aFailed;
      await until(() => server.closed == 1);
      answer(held);
      expect((await b.result).body.sublist(0, 2), u16(2));
      await expectAnswer(t, 3);
      expect(server.connections, 2);
      expect(server.exchanges.last.connection, held.connection);
      expect(server.closed, 1);
    });
  }

  test('an unsolicited response on an idle lane retires only that lane',
      () async {
    await serve((e) async {
      answer(e);
      if (e.index == 1) {
        await e.socket.flush();
        await Future<void>.delayed(const Duration(milliseconds: 50));
        answer(e);
      }
    });
    final t = transport(null);
    await expectAnswer(t, 1);
    await until(() => server.closed == 1);
    await expectAnswer(t, 2).timeout(const Duration(seconds: 2));
    expect(server.connections, 2);
    expect(server.exchanges.last.connection, 2);
  });

  test('JSON requests never consume a duplicate response from a prior request',
      () async {
    List<int> response(String value) => httpResponse(
        utf8.encode(jsonEncode({
          'Status': 0,
          'AD': true,
          'CD': false,
          'TC': false,
          'Question': [
            {'name': 'alice.example.', 'type': 16}
          ],
          'Answer': [
            {'name': 'alice.example.', 'type': 16, 'TTL': 60, 'data': value}
          ]
        })),
        type: 'application/json');
    await serve((e) async {
      if (e.index == 1) {
        e.send(response('old'));
        await e.socket.flush();
        await Future<void>.delayed(const Duration(milliseconds: 10));
        e.send(response('old'));
      } else {
        await Future<void>.delayed(const Duration(milliseconds: 100));
        e.send(response('new'));
      }
    });
    final t = transport(null);
    final resolver = DohResolver(
        transport: t,
        endpoint: Uri.parse('https://localhost:${server.port}/resolve'));
    expect(
        (await resolver.lookupTxt('alice.example')).records.single.text, 'old');
    expect(
        (await resolver.lookupTxt('alice.example')).records.single.text, 'new');
    expect(server.connections, 2);
  });

  test('a wire transaction ID is never reused on one connection', () async {
    await serve((e) async {
      if (e.index == 1) {
        e.send(httpResponse(wireReply(id: e.id, flags: 0x8183)));
        await e.socket.flush();
        await Future<void>.delayed(const Duration(milliseconds: 10));
        e.send(httpResponse(wireReply(id: e.id, flags: 0x8183)));
      } else {
        await Future<void>.delayed(const Duration(milliseconds: 100));
        answer(e);
      }
    });
    final t = transport(null);
    expect((await start(t, 0x1111).result).body[3] & 0xf, 3);
    expect((await start(t, 0x1111).result).body[3] & 0xf, 0);
    expect(server.connections, 2);
  });

  test('a connection closed by the server while idle is not reused', () async {
    await serve((e) async {
      answer(e);
      await e.socket.flush();
      await e.socket.close();
    });
    final t = transport(null);
    await expectAnswer(t, 1);
    await Future<void>.delayed(const Duration(milliseconds: 100));
    await expectAnswer(t, 2);
    expect(server.connections, 2);
  });

  test('lanes never exceed maxConcurrentRequests', () async {
    await serve(answer);
    final t = transport(null, maxConcurrentRequests: 2);
    await Future.wait([for (var id = 1; id <= 6; id++) expectAnswer(t, id)]);
    expect(server.connections, lessThanOrEqualTo(2));
  });

  test('a reusable lane is pinned to one HTTPS origin', () async {
    await serve(answer);
    final other = ScriptedServer(pki.serverContext(), answer);
    await other.start();
    addTearDown(other.close);
    final t = transport(null, maxConcurrentRequests: 1);
    DnsOperation<DohHttpResponse> startAt(ScriptedServer target, int id) =>
        t.startWire(Uri.parse('https://localhost:${target.port}/dns-query'),
            wireQuery(id: id),
            maxResponseBytes: 512);

    await startAt(server, 1).result;
    await startAt(other, 2).result;
    await startAt(server, 3).result;
    expect(server.connections, 2,
        reason: 'returning to an origin must not revive its retired pool');
    expect(other.connections, 1);
  });

  test('idle connections are released without close', () async {
    await serve(answer);
    final t = transport(null, idleTimeout: const Duration(milliseconds: 200));
    await expectAnswer(t, 1);
    expect(server.closed, 0);
    await until(() => server.closed == 1);
    await expectAnswer(t, 2);
    expect(server.connections, 2);
  });

  test('close fails queued and in-flight requests and later starts', () async {
    await serve((e) {
      if (e.index == 1) answer(e);
    });
    final t = transport(null, maxConcurrentRequests: 1);
    await expectAnswer(t, 1);
    final inFlight = start(t, 2);
    final queued = start(t, 3);
    final failed = [
      for (final operation in [inFlight, queued])
        expectLater(operation.result, throwsA(error(DnsError.cancelled)))
    ];
    await until(() => server.exchanges.length == 2);
    await t.close();
    await Future.wait(failed);
    await until(() => server.closed == 1);
    await expectLater(start(t, 4).result, throwsA(error(DnsError.cancelled)));
    expect(server.connections, 1);
  });

  test('close cancels a pending SOCKS connection', () async {
    await serve(answer);
    final proxy = TunnelProxy(upstreamPort: server.port, stallAt: 1);
    await proxy.start();
    addTearDown(proxy.close);
    final t = transport(proxy);
    final failed =
        expectLater(start(t, 1).result, throwsA(error(DnsError.cancelled)));
    await proxy.connected.future;
    await t.close();
    await failed;
    await proxy.disconnected.future.timeout(const Duration(seconds: 2));
    expect(server.connections, 0);
  });

  test('close releases idle connections', () async {
    await serve(answer);
    final t = transport(null);
    await expectAnswer(t, 1);
    await t.close();
    await until(() => server.closed == 1);
  });
}
