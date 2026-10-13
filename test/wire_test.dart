import 'dart:math';

import 'package:doh_resolver/doh_resolver.dart';
import 'package:test/test.dart';

import 'support/dns_wire.dart';

const pointer = [0xc0, 12];

void main() {
  final query = wireQuery();

  test('accepts a complete reply with compressed names and DNSSEC records', () {
    final rrsig = [
      ...u16(16), 13, 2, 0, 0, 0, 60, //
      0, 0, 0, 0, 0, 0, 0, 0, ...u16(1),
      ...wireName('example'), 1, 2, 3
    ];
    validateDnsWireResponse(
        query,
        wireReply(answers: [
          wireRecord(pointer, 5, [3, ...'pay'.codeUnits, 0xc0, 18]),
          wireRecord(wireName('pay.example'), 16, txtRdata('oa1:xmr')),
          wireRecord(wireName('pay.example'), 46, rrsig),
        ]));
    validateDnsWireResponse(query, wireReply(flags: 0x8183));
  });

  test('parses every RFC 1035 legacy name-bearing RDATA format', () {
    for (final type in [3, 4, 7, 8, 9]) {
      validateDnsWireResponse(
          query, wireReply(answers: [wireRecord(pointer, type, pointer)]));
    }
    validateDnsWireResponse(
        query,
        wireReply(answers: [
          wireRecord(pointer, 14, [...pointer, ...pointer])
        ]));
  });

  test('registers every pre-RFC 3597 embedded domain name', () {
    final first = wireName('first.example');
    final second = wireName('second.example');
    final characterStrings = [1, 0x66, 1, 0x73, 1, 0x72];
    final cases = <(int, List<int>, List<int>)>[
      (17, [...first, ...second], [0, first.length]),
      (18, [0, 1, ...first], [2]),
      (21, [0, 1, ...first], [2]),
      (24, [...List.filled(18, 0), ...first, 1], [18]),
      (26, [0, 1, ...first, ...second], [2, 2 + first.length]),
      (30, [...first, 0, 0, 0, 1], [0]),
      (33, [...List.filled(6, 0), ...first], [6]),
      (
        35,
        [...List.filled(4, 0), ...characterStrings, ...first],
        [4 + characterStrings.length]
      ),
      (36, [0, 1, ...first], [2]),
      (38, [128, ...first], [1]),
      (39, first, [0]),
    ];
    for (final (type, rdata, offsets) in cases) {
      for (final offset in offsets) {
        validateDnsWireResponse(
            query, _ownerPointerIntoRdata(type, rdata, offset));
      }
    }
  });

  test('registers uncompressed names embedded in newer RDATA types', () {
    final first = wireName('first.example');
    final second = wireName('second.example');
    final cases = <(int, List<int>, List<int>)>[
      // SVCB and HTTPS: priority, TargetName, then SvcParams.
      (64, [0, 1, ...first], [2]),
      (65, [0, 1, ...first, 0, 1, 0, 2, 0x68, 0x32], [2]),
      // HIP: HIT and public key, then rendezvous servers.
      (
        55,
        [2, 1, 0, 1, 0xaa, 0xbb, 0xcc, ...first, ...second],
        [7, 7 + first.length]
      ),
      (58, [...first, ...second], [0, first.length]),
      (107, [0, 1, ...first], [2]),
      (249, [...first, ...List.filled(16, 0)], [0]),
      (250, [...first, ...List.filled(16, 0)], [0]),
      // AMTRELAY with a domain-name relay (type 3).
      (260, [0, 3, ...first], [2]),
      (23, first, [0]),
      // IPSECKEY with a domain-name gateway (type 3), then the public key.
      (45, [10, 3, 2, ...first, 1, 2, 3], [3]),
      // DSYNC: RRtype, scheme and port, then the target.
      (66, [0, 59, 1, 0x14, 0xeb, ...first], [5]),
    ];
    for (final (type, rdata, offsets) in cases) {
      validateDnsWireResponse(
          query, wireReply(answers: [wireRecord(pointer, type, rdata)]));
      for (final offset in offsets) {
        validateDnsWireResponse(
            query, _ownerPointerIntoRdata(type, rdata, offset));
      }
    }
  });

  test('newer RDATA names must not be compressed or overrun', () {
    for (final (type, rdata) in <(int, List<int>)>[
      (64, [0, 1, ...pointer]),
      (65, [0, 1, ...pointer]),
      (55, [1, 1, 0, 0, 0xaa, ...pointer]),
      (55, [4, 1, 0, 0, 0xaa]),
      (58, [...pointer, 0]),
      (58, [0]),
      (107, [0, 1, 0, 0]),
      (250, [...pointer]),
      (260, [0, 3, ...pointer]),
      (260, [0, 1, 1, 2, 3]),
      (260, [0, 0, 1]),
      (23, pointer),
      (45, [10, 3, 2, ...pointer]),
      (45, [10, 1, 2, 1, 2, 3]),
      (66, [0, 59, 1, 0x14, 0xeb, ...pointer]),
      (66, [0, 59, 1, 0x14, 0xeb, 0, 1]),
    ]) {
      expect(
          () => validateDnsWireResponse(
              query, wireReply(answers: [wireRecord(pointer, type, rdata)])),
          throwsA(isA<DnsMalformedResponseException>()),
          reason: 'type $type rdata $rdata');
    }
    for (final (type, rdata) in <(int, List<int>)>[
      (260, [0, 1, 1, 2, 3, 4]),
      (260, [0, 2, ...List.filled(16, 0)]),
      (260, [0, 0]),
      (45, [10, 0, 2, 1, 2, 3]),
      (45, [10, 1, 2, 1, 2, 3, 4, 9]),
      (45, [10, 2, 0, ...List.filled(16, 0)]),
    ]) {
      validateDnsWireResponse(
          query, wireReply(answers: [wireRecord(pointer, type, rdata)]));
    }
  });

  test('accepts legacy RDATA compression required for compatibility', () {
    for (final (type, rdata) in <(int, List<int>)>[
      (17, [...pointer, ...pointer]),
      (18, [0, 1, ...pointer]),
      (21, [0, 1, ...pointer]),
      (24, [...List.filled(18, 0), ...pointer, 1]),
      (26, [0, 1, ...pointer, ...pointer]),
      (30, [...pointer, 0, 0, 0, 1]),
      (33, [...List.filled(6, 0), ...pointer]),
      (35, [...List.filled(4, 0), 0, 0, 0, ...pointer]),
    ]) {
      validateDnsWireResponse(
          query, wireReply(answers: [wireRecord(pointer, type, rdata)]));
    }
  });

  test('question comparison ignores ASCII case only', () {
    validateDnsWireResponse(query, wireReply(name: 'ALICE.example'));
    expect(
        () => validateDnsWireResponse(query, wireReply(name: 'alicf.example')),
        throwsA(isA<DnsQuestionMismatchException>()));
  });

  test('rejects replies that do not answer the query', () {
    for (final reply in [
      wireReply(id: 0x4321),
      wireReply(flags: 0x8980),
      wireReply(name: 'bob.example'),
      [...wireHeader(flags: 0x8180, qd: 0)],
      wireReply()..[query.length - 11 - 3] = 1,
      wireReply()..[query.length - 11 - 1] = 3,
    ]) {
      expect(() => validateDnsWireResponse(query, reply),
          throwsA(isA<DnsQuestionMismatchException>()));
    }
  });

  test('rejects queries, truncated replies and unsupported EDNS versions', () {
    for (final reply in [
      query,
      wireReply(flags: 0x8380),
      wireReply()..[query.length - 5] = 1,
    ]) {
      expect(() => validateDnsWireResponse(query, reply),
          throwsA(isA<DnsMalformedResponseException>()));
    }
    expect(() => validateDnsWireResponse(wireReply(), wireReply()),
        throwsA(isA<DnsInvalidQueryException>()));
  });

  group('hostile messages fail closed', () {
    final cases = <String, List<int>>{
      'short header': wireReply().sublist(0, 11),
      'question past end': wireReply().sublist(0, 20),
      'trailing bytes': [...wireReply(), 0],
      'answer count beyond data': wireReply()..[7] = 255,
      'additional count beyond data': wireReply()..[11] = 2,
      'rdlength beyond data': wireReply(
          answers: [wireRecord(pointer, 16, txtRdata('x')).sublist(0, 12)]),
      'pointer into header': wireReply(answers: [
        wireRecord([0xc0, 4], 16, txtRdata('x'))
      ]),
      'pointer into question type': wireReply(answers: [
        wireRecord([0xc0, 27], 16, txtRdata('x'))
      ]),
      'forward pointer': wireReply(answers: [
        wireRecord([0xc0, 200], 16, txtRdata('x'))
      ]),
      'self pointer': _withOwnerAt((at) => [1, 0x61, 0xc0, at]),
      'pointer loop through earlier labels': _loop(),
      'extended label type': wireReply(answers: [
        wireRecord([0x41, 0], 16, txtRdata('x'))
      ]),
      'label past end': [...wireHeader(flags: 0x8180), 40, 0x61],
      'name over 255 octets': wireReply(answers: [
        wireRecord([
          for (var i = 0; i < 5; i++) ...[63, ...List.filled(63, 0x61)],
          0
        ], 16, txtRdata('x'))
      ]),
      'compressed name over 255 octets': _longCompressedName(),
      'OPT in answers': wireReply(answers: [wireOpt()]),
      'two OPT records': wireReply(additional: [wireOpt()]),
      'OPT with non-root owner':
          wireReply(additional: [wireOpt(owner: wireName('example'))]),
      'OPT option overrun': [
        ...wireHeader(flags: 0x8180, ar: 1),
        ...wireQuestion(wireName('alice.example')),
        ...wireOpt(options: [0, 12, 0, 9, 0])
      ],
      'CNAME target overruns rdata': wireReply(answers: [
        wireRecord(pointer, 5, [3, 0x61, 0x62])
      ]),
      'CNAME junk after target': wireReply(answers: [
        wireRecord(pointer, 5, [...pointer, 0])
      ]),
      'compressed RRSIG signer': wireReply(answers: [
        wireRecord(pointer, 46, [...List.filled(18, 0), ...pointer, 1])
      ]),
      'SOA without counters': wireReply(answers: [
        wireRecord(pointer, 6, [...pointer, ...pointer, 0, 0, 0])
      ]),
      'legacy name pointer into header': wireReply(answers: [
        wireRecord(pointer, 7, [0xc0, 4])
      ]),
      'MINFO missing second name':
          wireReply(answers: [wireRecord(pointer, 14, pointer)]),
      'RP name pointer into header': wireReply(answers: [
        wireRecord(pointer, 17, [0xc0, 4, ...pointer])
      ]),
      'NAPTR truncated character string': wireReply(answers: [
        wireRecord(pointer, 35, [...List.filled(4, 0), 2, 0])
      ]),
      'compressed KX exchanger': wireReply(answers: [
        wireRecord(pointer, 36, [0, 1, ...pointer])
      ]),
      'compressed A6 prefix name': wireReply(answers: [
        wireRecord(pointer, 38, [128, ...pointer])
      ]),
    };
    cases.forEach((name, reply) {
      test(name, () {
        expect(() => validateDnsWireResponse(query, reply),
            throwsA(isA<DnsException>()));
      });
    });
  });

  test('random corruption never escapes as a non-DNS error', () {
    final random = Random(8484);
    final valid = wireReply(answers: [
      wireRecord(pointer, 5, [3, ...'pay'.codeUnits, 0xc0, 18]),
      wireRecord(wireName('pay.example'), 16, txtRdata('oa1:xmr')),
    ]);
    for (var i = 0; i < 5000; i++) {
      final reply = [...valid];
      for (var j = random.nextInt(4); j >= 0; j--) {
        reply[random.nextInt(reply.length)] = random.nextInt(256);
      }
      final cut = random.nextInt(8) == 0 ? random.nextInt(reply.length) : null;
      try {
        validateDnsWireResponse(
            query, cut == null ? reply : reply.sublist(0, cut));
      } on DnsException {
        // Expected for most mutations.
      }
    }
  });

  group('wire TTL adjustment', () {
    int ttlAt(List<int> message, int at) =>
        message[at] << 24 |
        message[at + 1] << 16 |
        message[at + 2] << 8 |
        message[at + 3];

    test('ages record TTLs and leaves OPT and the input untouched', () {
      final txt = wireRecord(pointer, 16, txtRdata('x'));
      final reply = wireReply(answers: [txt, txt], additional: [txt]);
      final original = [...reply];
      final head = wireReply().length - wireOpt().length;
      final ttls = [
        head + 6,
        head + txt.length + 6,
        head + 2 * txt.length + 6,
      ];
      final aged = adjustDnsWireTtls(reply, age: const Duration(seconds: 25));
      expect([for (final at in ttls) ttlAt(aged, at)], [35, 35, 35]);
      expect(aged.sublist(aged.length - wireOpt().length), wireOpt());
      expect(reply, original);
      validateDnsWireResponse(query, aged);
      expect(
          ttlAt(adjustDnsWireTtls(reply, age: const Duration(hours: 1)),
              ttls.first),
          0);
    });

    test('treats high-bit TTLs as zero', () {
      final reply =
          wireReply(answers: [wireRecord(pointer, 16, txtRdata('x'))]);
      final at = wireReply().length - wireOpt().length + 6;
      reply[at] = 0x80;
      expect(ttlAt(adjustDnsWireTtls(reply, age: Duration.zero), at), 0);
    });

    test('rejects malformed messages and negative ages', () {
      expect(() => adjustDnsWireTtls([0, 1, 2], age: Duration.zero),
          throwsA(isA<DnsMalformedResponseException>()));
      final empty = wireHeader(flags: 0x8180, qd: 0);
      expect(() => adjustDnsWireTtls(empty, age: const Duration(seconds: -1)),
          throwsArgumentError,
          reason: 'even with no TTL to adjust');
    });
  });

  test('effectiveDnsTtl applies RFC 2181 and the HTTP age', () {
    expect(effectiveDnsTtl(600), 600);
    expect(effectiveDnsTtl(600, age: const Duration(seconds: 250)), 350);
    expect(effectiveDnsTtl(60, age: const Duration(seconds: 61)), 0);
    expect(effectiveDnsTtl(0x7fffffff), 0x7fffffff);
    expect(effectiveDnsTtl(0x80000000), 0);
    for (final ttl in [-1, 0x100000000]) {
      expect(() => effectiveDnsTtl(ttl), throwsArgumentError);
    }
    expect(() => effectiveDnsTtl(1, age: const Duration(seconds: -1)),
        throwsArgumentError);
  });

  group('query padding', () {
    test('pads a final OPT record to a 128-octet block', () {
      final padded = padDnsWireQuery(query);
      expect(padded.length % 128, 0);
      final option = padded.sublist(query.length);
      expect(option.sublist(0, 2), [0, 12]);
      expect(option.sublist(2, 4), u16(padded.length - query.length - 4));
      expect(option.skip(4), everyElement(0));
      expect(padded.sublist(query.length - 2, query.length),
          u16(padded.length - query.length));
      validateDnsWireResponse(padded, wireReply());
      expect(padDnsWireQuery(padded), padded);
    });

    test('leaves queries without a final OPT record unchanged', () {
      final plain = wireQuery(edns: false);
      expect(padDnsWireQuery(plain), plain);
      final optFirst = [
        ...wireHeader(ar: 2),
        ...wireQuestion(wireName('alice.example')),
        ...wireOpt(),
        ...wireRecord([0], 16, txtRdata('x'))
      ];
      expect(padDnsWireQuery(optFirst), optFirst);
    });

    test('rejects invalid queries', () {
      for (final bad in [
        <int>[],
        [...query, 0],
        wireReply(),
        [...query]..[0] = 256,
      ]) {
        expect(() => padDnsWireQuery(bad),
            throwsA(isA<DnsInvalidQueryException>()));
      }
    });
  });
}

List<int> _withOwnerAt(List<int> Function(int at) owner) {
  final prefix = wireReply().length - wireOpt().length;
  return wireReply(answers: [wireRecord(owner(prefix), 16, txtRdata('x'))]);
}

List<int> _loop() {
  final head = wireReply().length - wireOpt().length;
  final label = head + 11 + 2;
  return wireReply(answers: [
    wireRecord([0], 99, [0, 1, 0x61, 0xc0, label - 1]),
    wireRecord([0xc0, label - 1], 16, txtRdata('x')),
  ]);
}

List<int> _ownerPointerIntoRdata(int type, List<int> rdata, int offset) {
  final head = wireReply().length - wireOpt().length;
  final target = head + 11 + offset;
  return wireReply(answers: [
    wireRecord([0], type, rdata),
    wireRecord([0xc0 | target >> 8, target & 0xff], 16, txtRdata('x')),
  ]);
}

List<int> _longCompressedName() {
  final head = wireReply().length - wireOpt().length;
  final first = [
    for (var i = 0; i < 3; i++) ...[63, ...List.filled(63, 0x61)],
    0
  ];
  return wireReply(answers: [
    wireRecord(first, 16, txtRdata('x')),
    wireRecord([63, ...List.filled(63, 0x62), 0xc0, head], 16, txtRdata('x')),
  ]);
}
