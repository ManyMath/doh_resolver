import 'dart:async';
import 'dart:convert';
import 'package:doh_resolver/doh_resolver.dart';
import 'package:test/test.dart';

Map<String, Object?> reply({List<Map<String, Object?>>? answers}) => {
      'Status': 0,
      'AD': true,
      'CD': false,
      'TC': false,
      'Question': [
        {'name': 'alice.example.', 'type': 16}
      ],
      'Answer': answers ??
          [rr('alice.example.', 16, 'oa1:xmr recipient_address=valid;')],
    };
Map<String, Object?> rr(String name, int type, String data) => {
      'name': name,
      'type': type,
      'TTL': 60,
      'data': data,
    };
DnsResponse decode(Object? json) => DnsResponse.fromJson(json,
    resolver: Uri.parse('https://dns.example/resolve'));

class FakeTransport implements DohTransport {
  final completer = Completer<DohHttpResponse>();
  bool cancelled = false;
  bool throwOnCancel = false;
  Uri? uri;
  @override
  DnsOperation<DohHttpResponse> start(Uri uri,
      {required int maxResponseBytes}) {
    this.uri = uri;
    return DnsOperation(completer.future, () {
      cancelled = true;
      if (throwOnCancel) throw StateError('cancel failed');
    });
  }
}

void main() {
  test('only terminal-owner TXT answers are accepted; evidence retained', () {
    final response = decode(reply(answers: [
      rr('alice.example.', 5, 'pay.example.'),
      rr('pay.example.', 16, 'one'),
      rr('pay.example.', 16, 'two'),
      rr('evil.example.', 16, 'evil')
    ]));
    final result = response.authenticatedTxt('Alice.Example.',
        txtFormat: DnsTxtFormat.raw);
    expect(result.records.map((r) => r.text), ['one', 'two']);
    expect(result.canonicalName, 'pay.example');
    expect(result.aliases, hasLength(1));
    expect(result.response, same(response));
    expect(result.records.first.ttl, 60);
    // ignore: deprecated_member_use_from_same_package
    expect(result, isA<AuthenticatedTxtResult>());
  });
  for (final field in ['AD', 'CD', 'TC']) {
    test('missing or unacceptable $field never authenticates', () {
      for (final body in [
        reply()..remove(field),
        reply()..[field] = field != 'AD'
      ]) {
        expect(
            () => decode(body)
                .authenticatedTxt('alice.example', txtFormat: DnsTxtFormat.raw),
            throwsA(isA<DnsAuthenticationUnavailableException>()));
      }
    });
  }
  test('DNS error preserves status without inferring bogus or unsigned', () {
    expect(
        () => decode(reply()..['Status'] = 2)
            .authenticatedTxt('alice.example', txtFormat: DnsTxtFormat.raw),
        throwsA(
            isA<DnsQueryFailedException>().having((e) => e.rcode, 'rcode', 2)));
  });
  test('HTTP failures carry the status', () async {
    final transport = FakeTransport();
    final result = DohResolver(transport: transport).lookupTxt('alice.example');
    transport.completer.complete(DohHttpResponse(503, []));
    await expectLater(
        result,
        throwsA(isA<DnsTransportException>()
            .having((e) => e.httpStatus, 'httpStatus', 503)));
  });
  test('the exception hierarchy is sealed and exhaustive', () {
    String describe(DnsException error) => switch (error) {
          DnsInvalidNameException() => 'name',
          DnsInvalidQueryException() => 'query',
          DnsMalformedResponseException() => 'malformed',
          DnsResponseTooLargeException() => 'large',
          DnsQueryFailedException(:final rcode) => 'rcode $rcode',
          DnsAuthenticationUnavailableException() => 'unauthenticated',
          DnsQuestionMismatchException() => 'mismatch',
          DnsAliasException() => 'alias',
          DnsTransportException(:final httpStatus) => 'http $httpStatus',
          DnsCancelledException() => 'cancelled',
          DnsTimeoutException() => 'timeout',
        };
    expect(describe(const DnsAliasLoopException('loop')), 'alias');
    expect(describe(const DnsQueryFailedException('x', rcode: 3)), 'rcode 3');
    expect(const DnsTimeoutException('late').toString(),
        'DnsTimeoutException: late');
  });
  for (final questions in [
    <Object>[],
    [
      {'name': 'other.example', 'type': 16}
    ],
    [
      {'name': 'alice.example', 'type': 1}
    ],
    [
      {'name': 'alice.example', 'type': 16},
      {'name': 'alice.example', 'type': 16}
    ]
  ]) {
    test('rejects mismatched questions $questions', () {
      expect(
          () => decode(reply()..['Question'] = questions)
              .authenticatedTxt('alice.example', txtFormat: DnsTxtFormat.raw),
          throwsA(isA<DnsQuestionMismatchException>()));
    });
  }
  test('no answers is distinct from DNS failure', () {
    expect(
        decode(reply()..remove('Answer'))
            .authenticatedTxt('alice.example', txtFormat: DnsTxtFormat.raw)
            .records,
        isEmpty);
  });
  test('rejects loops, ambiguous owners and excessive chains', () {
    expect(
        () => decode(reply(answers: [rr('alice.example', 5, 'alice.example')]))
            .authenticatedTxt('alice.example', txtFormat: DnsTxtFormat.raw),
        throwsA(isA<DnsAliasLoopException>()));
    for (final records in [
      [rr('alice.example', 5, 'pay.example'), rr('alice.example', 16, 'txt')],
      [
        rr('alice.example', 5, 'pay.example'),
        rr('alice.example', 5, 'pay.example')
      ]
    ]) {
      expect(
          () => decode(reply(answers: records))
              .authenticatedTxt('alice.example', txtFormat: DnsTxtFormat.raw),
          throwsA(isA<DnsAliasAmbiguousException>()));
    }
    final chain = [
      rr('alice.example', 5, 'hop0.example'),
      for (var i = 0; i < 7; i++) rr('hop$i.example', 5, 'hop${i + 1}.example'),
      rr('hop7.example', 16, 'txt')
    ];
    expect(
        () => decode(reply(answers: chain))
            .authenticatedTxt('alice.example', txtFormat: DnsTxtFormat.raw),
        throwsA(isA<DnsAliasTooLongException>()));
  });
  test('rejects invalid TTLs, names, record data, types and response shape',
      () {
    for (final body in [
      null,
      [],
      reply()..['Answer'] = 'bad',
      reply()..['AD'] = 'true',
      reply(answers: [rr('alice.example', 16, 'x')..['TTL'] = -1]),
      reply(answers: [rr('alice.example', 16, 'x')..['TTL'] = 0x100000000]),
      reply(answers: [rr('alice.example', 16, 'x')..['data'] = 7]),
      reply(answers: [rr('alice.example', 16, 'x')..['type'] = '16']),
      reply(answers: [rr('alice.example', 16, 'x')..['type'] = 0x10000]),
      reply()
        ..['Question'] = [
          {'name': 'alice.example', 'type': -1}
        ],
      reply(answers: [rr('K.example', 16, 'x')])
    ]) {
      expect(() => decode(body), throwsA(isA<DnsException>()));
    }
    expect(
        () => decode(reply(
            answers: List.generate(65, (_) => rr('alice.example', 16, 'x')))),
        throwsA(isA<DnsResponseTooLargeException>()));
  });
  test('TXT chunks and decimal UTF-8 octets are decoded without loss', () {
    expect(
        utf8.decode(decodeDnsTxtBytes(
            r'"oa1:xmr recipient_" "address=valid;"', DnsTxtFormat.quoted)),
        'oa1:xmr recipient_address=valid;');
    expect(
        utf8.decode(
            decodeDnsTxtBytes(r'"\195\169\032\""', DnsTxtFormat.quoted)),
        'é "');
    expect(utf8.decode(decodeDnsTxtBytes('"emoji 😀"', DnsTxtFormat.quoted)),
        'emoji 😀');
    expect(decodeDnsTxtBytes(r'"\255"', DnsTxtFormat.quoted), [255]);
    expect(utf8.decode(decodeDnsTxtBytes('"\\😀"', DnsTxtFormat.quoted)), '😀');
    expect(() => DnsTxtRecord(name: 'x', ttl: 1, bytes: [255]).text,
        throwsA(isA<DnsMalformedResponseException>()));
  });
  test('TTLs with the high bit set are treated as zero', () {
    for (final (raw, ttl) in [(0x7fffffff, 0x7fffffff), (0x80000000, 0)]) {
      final result = decode(reply(answers: [
        rr('alice.example', 5, 'pay.example')..['TTL'] = raw,
        rr('pay.example', 16, 'x')..['TTL'] = raw,
      ])).authenticatedTxt('alice.example', txtFormat: DnsTxtFormat.raw);
      expect(result.records.single.ttl, ttl);
      expect(result.aliases.single.ttl, ttl);
    }
  });
  test('raw TXT is taken verbatim and quoted TXT must be quoted', () {
    for (final value in ['"hello"', r'\065 x', '"unmatched']) {
      expect(utf8.decode(decodeDnsTxtBytes(value, DnsTxtFormat.raw)), value);
    }
    expect(() => decodeDnsTxtBytes('lone \ud800', DnsTxtFormat.raw),
        throwsA(isA<DnsMalformedResponseException>()));
    expect(decodeDnsTxtBytes('""', DnsTxtFormat.quoted), isEmpty);
    expect(decodeDnsTxtBytes(' "" "" ', DnsTxtFormat.quoted), isEmpty);
    for (final value in ['hello', 'a "b"', '', '   ']) {
      expect(() => decodeDnsTxtBytes(value, DnsTxtFormat.quoted),
          throwsA(isA<DnsMalformedResponseException>()));
    }
  });
  test('known resolvers get their TXT format; others must choose', () {
    DnsTxtFormat formatOf(String url) =>
        DohResolver(transport: FakeTransport(), endpoint: Uri.parse(url))
            .txtFormat;
    expect(DohResolver(transport: FakeTransport()).txtFormat, DnsTxtFormat.raw);
    expect(formatOf('https://dns.google/resolve'), DnsTxtFormat.raw);
    for (final host in [
      'cloudflare-dns.com',
      'security.cloudflare-dns.com',
      'one.one.one.one',
      '1.1.1.1'
    ]) {
      expect(formatOf('https://$host/dns-query'), DnsTxtFormat.quoted);
    }
    expect(() => formatOf('https://resolver.example/resolve'),
        throwsArgumentError);
    expect(
        DohResolver(
                transport: FakeTransport(),
                endpoint: Uri.parse('https://dns.google/resolve'),
                txtFormat: DnsTxtFormat.quoted)
            .txtFormat,
        DnsTxtFormat.quoted);
  });
  for (final (endpoint, data, text) in [
    ('https://dns.google/resolve', '"hello"', '"hello"'),
    ('https://cloudflare-dns.com/dns-query', r'"hel" "lo\033"', 'hello!'),
  ]) {
    test('$endpoint TXT $data decodes to $text', () async {
      final transport = FakeTransport();
      final result =
          DohResolver(transport: transport, endpoint: Uri.parse(endpoint))
              .lookupTxt('alice.example');
      transport.completer.complete(DohHttpResponse(
          200,
          utf8.encode(
              jsonEncode(reply(answers: [rr('alice.example', 16, data)])))));
      expect((await result).records.single.text, text);
    });
  }
  test('malformed and overlong TXT cannot turn into recipient data', () {
    for (final s in [
      '"unterminated',
      '"one" junk',
      r'"\999"',
      r'"\12"',
      r'"\1"',
      r'"\1x2"',
      '"trailing\\',
      'lone \ud800',
      '"lone \udc00"',
      '"\\\ud800"',
      '"\ud800 x"',
    ]) {
      expect(() => decodeDnsTxtBytes(s, DnsTxtFormat.quoted),
          throwsA(isA<DnsMalformedResponseException>()));
    }
    expect(() => decodeDnsTxtBytes('a' * 8193, DnsTxtFormat.quoted),
        throwsA(isA<DnsResponseTooLargeException>()));
  });
  test('DNS names allow service labels without permitting alias syntax', () {
    expect(normalizeDnsName('_Dmarc.Example.'), '_dmarc.example');
    for (final name in [
      'a@b.example',
      'K.example',
      'a..example',
      'https://example.org'
    ]) {
      expect(() => normalizeDnsName(name),
          throwsA(isA<DnsInvalidNameException>()));
    }
  });
  test('requests privacy flags and propagates evidence', () async {
    final transport = FakeTransport();
    final resolver = DohResolver(transport: transport);
    final query = resolver.startTxtLookup('alice.example');
    expect(transport.uri!.queryParameters, {
      'name': 'alice.example.',
      'type': 'TXT',
      'do': 'true',
      'cd': 'false',
      'edns_client_subnet': '0.0.0.0/0',
      'random_padding': matches(r'^X+$'),
    });
    expect(transport.uri.toString().length % 128, 0);
    transport.completer
        .complete(DohHttpResponse(200, utf8.encode(jsonEncode(reply()))));
    expect((await query.result).records.single.text,
        'oa1:xmr recipient_address=valid;');
    query.cancel();
    expect(transport.cancelled, isFalse,
        reason: 'a completed transport operation is never cancelled');
  });
  test('repeated endpoint parameters survive; resolver keys override', () {
    final transport = FakeTransport();
    DohResolver(
            txtFormat: DnsTxtFormat.raw,
            transport: transport,
            endpoint: Uri.parse('https://dns.example/resolve'
                '?tag=first&tag=second&name=evil&type=A&type=AAAA'))
        .startTxtLookup('alice.example');
    final sent = transport.uri!.queryParametersAll;
    expect(sent['tag'], ['first', 'second']);
    expect(sent['name'], ['alice.example.']);
    expect(sent['type'], ['TXT']);
    expect(transport.uri.toString().length % 128, 0);
  });
  test('padding hides name length and keeps endpoint parameters', () {
    final lengths = <int>{};
    for (final name in ['a.example', 'abcd.example']) {
      final transport = FakeTransport();
      DohResolver(
              txtFormat: DnsTxtFormat.raw,
              transport: transport,
              endpoint: Uri.parse('https://dns.example/resolve?ct=x'))
          .startTxtLookup(name);
      expect(transport.uri!.queryParameters['ct'], 'x');
      expect(transport.uri!.queryParameters['name'], '$name.');
      lengths.add(transport.uri.toString().length);
    }
    expect(lengths, {128});
  });
  test('an invalid name fails the result without reaching the transport',
      () async {
    final transport = FakeTransport();
    final operation =
        DohResolver(transport: transport).startTxtLookup('a..example');
    await expectLater(
        operation.result, throwsA(isA<DnsInvalidNameException>()));
    operation.cancel();
    expect(transport.uri, isNull);
  });
  test('endpoints with undecodable parameters or ports are rejected up front',
      () {
    for (final endpoint in [
      'https://resolver.example/resolve?x=%FF',
      'https://resolver.example/resolve?%C3=1',
      'https://resolver.example:0/resolve',
      'https://resolver.example:70000/resolve',
      'https://resolver.example:99999999999999999999/resolve',
    ]) {
      expect(
          () => DohResolver(
              txtFormat: DnsTxtFormat.raw,
              transport: FakeTransport(),
              endpoint: Uri.parse(endpoint)),
          throwsArgumentError);
    }
  });
  test('a transport that throws on start fails the result', () async {
    for (final (thrown, expected) in [
      (const DnsCancelledException('closed'), isA<DnsCancelledException>()),
      (StateError('broken'), isA<DnsTransportException>()),
    ]) {
      final result = DohResolver(transport: _ThrowingTransport(thrown))
          .lookupTxt('a.example');
      await expectLater(result, throwsA(expected));
    }
  });
  test('a throwing transport cancel cannot escape the deadline', () async {
    final transport = FakeTransport()..throwOnCancel = true;
    final query = DohResolver(
            transport: transport, timeout: const Duration(milliseconds: 20))
        .startTxtLookup('alice.example');
    await expectLater(query.result, throwsA(isA<DnsTimeoutException>()));
    query.cancel();
  });
  for (final cancel in [true, false]) {
    test(
        '${cancel ? 'cancellation' : 'deadline'} aborts the underlying operation',
        () async {
      final transport = FakeTransport();
      final resolver = DohResolver(
          transport: transport, timeout: const Duration(milliseconds: 30));
      final query = resolver.startTxtLookup('alice.example');
      final failed = expectLater(
          query.result,
          throwsA(cancel
              ? isA<DnsCancelledException>()
              : isA<DnsTimeoutException>()));
      if (cancel) query.cancel();
      await failed;
      expect(transport.cancelled, isTrue);
      transport.completer
          .complete(DohHttpResponse(200, utf8.encode(jsonEncode(reply()))));
      await Future<void>.delayed(Duration.zero);
    });
  }
  test('HTTP cache age reduces TTLs and never drives them negative', () async {
    for (final (age, ttl) in [(0, 60), (25, 35), (60, 0), (250, 0)]) {
      final transport = FakeTransport();
      final result =
          DohResolver(transport: transport).lookupTxt('alice.example');
      transport.completer.complete(DohHttpResponse(
          200,
          utf8.encode(jsonEncode(reply(answers: [
            rr('alice.example', 5, 'pay.example'),
            rr('pay.example', 16, 'x'),
          ]))),
          age: Duration(seconds: age)));
      final txt = await result;
      expect(txt.records.single.ttl, ttl);
      expect(txt.aliases.single.ttl, ttl);
      expect(txt.response!.age, Duration(seconds: age));
    }
    expect(() => DohHttpResponse(200, [], age: const Duration(seconds: -1)),
        throwsArgumentError);
  });
  test('an unexpected parsing error still completes the lookup', () async {
    final transport = FakeTransport();
    final result = DohResolver(transport: transport).lookupTxt('alice.example');
    transport.completer.complete(_ThrowingResponse());
    await expectLater(result.timeout(const Duration(seconds: 1)),
        throwsA(isA<DnsMalformedResponseException>()));
  });
  test('rejects HTTP, JSON and injected response limit violations', () async {
    for (final response in [
      DohHttpResponse(302, []),
      DohHttpResponse(200, utf8.encode('bad json')),
      DohHttpResponse(200, List.filled(65537, 0))
    ]) {
      final transport = FakeTransport();
      final result =
          DohResolver(transport: transport).lookupTxt('alice.example');
      transport.completer.complete(response);
      await expectLater(result, throwsA(isA<DnsException>()));
      expect(transport.cancelled, isFalse);
    }
    final failing = FakeTransport();
    final failed = DohResolver(transport: failing).lookupTxt('alice.example');
    failing.completer.completeError(StateError('down'));
    await expectLater(failed, throwsA(isA<DnsTransportException>()));
    expect(failing.cancelled, isFalse);
  });
}

class _ThrowingResponse implements DohHttpResponse {
  @override
  int get statusCode => 200;
  @override
  Duration get age => Duration.zero;
  @override
  List<int> get body => throw StateError('broken body');
}

class _ThrowingTransport implements DohTransport {
  final Object error;
  _ThrowingTransport(this.error);
  @override
  DnsOperation<DohHttpResponse> start(Uri uri,
          {required int maxResponseBytes}) =>
      throw error;
}
