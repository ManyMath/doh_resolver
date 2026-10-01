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
Matcher error(DnsError code) =>
    isA<DnsException>().having((e) => e.code, 'code', code);

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
    final result = response.authenticatedTxt('Alice.Example.');
    expect(result.records.map((r) => r.text), ['one', 'two']);
    expect(result.canonicalName, 'pay.example');
    expect(result.aliases, hasLength(1));
    expect(result.response, same(response));
    expect(result.records.first.ttl, 60);
    expect(result.authentication, DnsAuthentication.resolverAsserted);
  });
  for (final field in ['AD', 'CD', 'TC']) {
    test('missing or unacceptable $field never authenticates', () {
      for (final body in [
        reply()..remove(field),
        reply()..[field] = field != 'AD'
      ]) {
        expect(() => decode(body).authenticatedTxt('alice.example'),
            throwsA(error(DnsError.authenticationUnavailable)));
      }
    });
  }
  test('DNS error preserves status without inferring bogus or unsigned', () {
    expect(
        () => decode(reply()..['Status'] = 2).authenticatedTxt('alice.example'),
        throwsA(error(DnsError.queryFailed)));
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
              .authenticatedTxt('alice.example'),
          throwsA(error(DnsError.questionMismatch)));
    });
  }
  test('no answers is distinct from DNS failure', () {
    expect(
        decode(reply()..remove('Answer'))
            .authenticatedTxt('alice.example')
            .records,
        isEmpty);
  });
  test('rejects loops, ambiguous owners and excessive chains', () {
    expect(
        () => decode(reply(answers: [rr('alice.example', 5, 'alice.example')]))
            .authenticatedTxt('alice.example'),
        throwsA(error(DnsError.aliasLoop)));
    for (final records in [
      [rr('alice.example', 5, 'pay.example'), rr('alice.example', 16, 'txt')],
      [
        rr('alice.example', 5, 'pay.example'),
        rr('alice.example', 5, 'pay.example')
      ]
    ]) {
      expect(
          () =>
              decode(reply(answers: records)).authenticatedTxt('alice.example'),
          throwsA(error(DnsError.aliasAmbiguous)));
    }
    final chain = [
      rr('alice.example', 5, 'hop0.example'),
      for (var i = 0; i < 7; i++) rr('hop$i.example', 5, 'hop${i + 1}.example'),
      rr('hop7.example', 16, 'txt')
    ];
    expect(
        () => decode(reply(answers: chain)).authenticatedTxt('alice.example'),
        throwsA(error(DnsError.aliasTooLong)));
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
        throwsA(error(DnsError.responseTooLarge)));
  });
  test('TXT chunks and decimal UTF-8 octets are decoded without loss', () {
    expect(
        utf8.decode(
            decodeDnsTxtBytes(r'"oa1:xmr recipient_" "address=valid;"')),
        'oa1:xmr recipient_address=valid;');
    expect(utf8.decode(decodeDnsTxtBytes(r'"\195\169\032\""')), 'é "');
    expect(utf8.decode(decodeDnsTxtBytes('"emoji 😀"')), 'emoji 😀');
    expect(decodeDnsTxtBytes(r'"\255"'), [255]);
    expect(utf8.decode(decodeDnsTxtBytes('"\\😀"')), '😀');
    expect(() => DnsTxtRecord(name: 'x', ttl: 1, bytes: [255]).text,
        throwsA(error(DnsError.malformedResponse)));
  });
  test('validated evidence enforces DNS TTL bounds', () {
    final issuer = DnsValidationIssuer('test');
    for (final ttl in [-1, 0x100000000]) {
      expect(
          () => issuer.issueTxt(
                  question: 'alice.example',
                  canonicalName: 'alice.example',
                  resolver: Uri.https('resolver.example', '/dns-query'),
                  records: [
                    DnsTxtRecord(name: 'alice.example', ttl: ttl, bytes: [1])
                  ]),
          throwsA(error(DnsError.malformedResponse)));
    }
    expect(
        issuer
            .issueTxt(
                question: 'alice.example',
                canonicalName: 'alice.example',
                resolver: Uri.https('resolver.example', '/dns-query'),
                records: [
                  DnsTxtRecord(
                      name: 'alice.example', ttl: 0xffffffff, bytes: [1])
                ])
            .records
            .single
            .ttl,
        0xffffffff);
  });
  test('malformed and overlong TXT cannot turn into recipient data', () {
    for (final s in [
      '"unterminated',
      '"one" junk',
      r'"\999"',
      r'"\12"',
      r'"\1"',
      r'"\1x2"',
      '"trailing\\'
    ]) {
      expect(() => decodeDnsTxtBytes(s),
          throwsA(error(DnsError.malformedResponse)));
    }
    expect(() => decodeDnsTxtBytes('a' * 8193),
        throwsA(error(DnsError.responseTooLarge)));
  });
  test('DNS names allow service labels without permitting alias syntax', () {
    expect(normalizeDnsName('_Dmarc.Example.'), '_dmarc.example');
    for (final name in [
      'a@b.example',
      'K.example',
      'a..example',
      'https://example.org'
    ]) {
      expect(
          () => normalizeDnsName(name), throwsA(error(DnsError.invalidName)));
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
    expect(transport.cancelled, isTrue);
  });
  test('padding hides name length and keeps endpoint parameters', () {
    final lengths = <int>{};
    for (final name in ['a.example', 'abcd.example']) {
      final transport = FakeTransport();
      DohResolver(
              transport: transport,
              endpoint: Uri.parse('https://dns.example/resolve?ct=x'))
          .startTxtLookup(name);
      expect(transport.uri!.queryParameters['ct'], 'x');
      expect(transport.uri!.queryParameters['name'], '$name.');
      lengths.add(transport.uri.toString().length);
    }
    expect(lengths, {128});
  });
  test('a throwing transport cancel cannot escape the deadline', () async {
    final transport = FakeTransport()..throwOnCancel = true;
    final query = DohResolver(
            transport: transport, timeout: const Duration(milliseconds: 20))
        .startTxtLookup('alice.example');
    await expectLater(query.result, throwsA(error(DnsError.timedOut)));
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
      final failed = expectLater(query.result,
          throwsA(error(cancel ? DnsError.cancelled : DnsError.timedOut)));
      if (cancel) query.cancel();
      await failed;
      expect(transport.cancelled, isTrue);
      transport.completer
          .complete(DohHttpResponse(200, utf8.encode(jsonEncode(reply()))));
      await Future<void>.delayed(Duration.zero);
    });
  }
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
      expect(transport.cancelled, isTrue);
    }
  });
}
