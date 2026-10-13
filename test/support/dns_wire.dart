import 'dart:convert';

List<int> wireName(String name) => [
      for (final label in name.split('.').where((l) => l.isNotEmpty)) ...[
        label.length,
        ...ascii.encode(label)
      ],
      0
    ];

List<int> wireHeader(
        {int id = 0x1234,
        int flags = 0x0100,
        int qd = 1,
        int an = 0,
        int ns = 0,
        int ar = 0}) =>
    [
      for (final v in [id, flags, qd, an, ns, ar]) ...u16(v)
    ];

List<int> u16(int value) => [value >> 8 & 0xff, value & 0xff];

List<int> wireQuestion(List<int> name, {int type = 16, int dnsClass = 1}) =>
    [...name, ...u16(type), ...u16(dnsClass)];

List<int> wireRecord(List<int> owner, int type, List<int> rdata,
        {int dnsClass = 1}) =>
    [
      ...owner,
      ...u16(type),
      ...u16(dnsClass),
      0,
      0,
      0,
      60,
      ...u16(rdata.length),
      ...rdata
    ];

List<int> wireOpt(
        {List<int> options = const [],
        int version = 0,
        List<int> owner = const [0]}) =>
    [
      ...owner,
      ...u16(41),
      ...u16(1232),
      0,
      version,
      0x80,
      0,
      ...u16(options.length),
      ...options
    ];

List<int> wireQuery(
        {String name = 'alice.example',
        int id = 0x1234,
        bool edns = true,
        int type = 16}) =>
    [
      ...wireHeader(id: id, ar: edns ? 1 : 0),
      ...wireQuestion(wireName(name), type: type),
      if (edns) ...wireOpt(),
    ];

List<int> wireReply(
        {String name = 'alice.example',
        int id = 0x1234,
        int flags = 0x8180,
        List<List<int>> answers = const [],
        List<List<int>> additional = const []}) =>
    [
      ...wireHeader(
          id: id, flags: flags, an: answers.length, ar: additional.length + 1),
      ...wireQuestion(wireName(name)),
      for (final answer in answers) ...answer,
      for (final record in additional) ...record,
      ...wireOpt(),
    ];

List<int> txtRdata(String text) => [text.length, ...ascii.encode(text)];

/// A NOERROR reply that echoes [query]'s ID, question and OPT record.
List<int> wireEcho(List<int> query) => [...query]
  ..[2] = 0x81
  ..[3] = 0x80;

String wireFirstLabel(List<int> message) =>
    ascii.decode(message.sublist(13, 13 + message[12]));

/// A query whose last additional record is a SIG(0) (type 24) or TSIG
/// (type 250); both sign the header, including the ID.
List<int> wireSignedQuery({int id = 0x1234, int type = 24}) => [
      ...wireHeader(id: id, ar: 2),
      ...wireQuestion(wireName('alice.example')),
      ...wireOpt(),
      ...wireRecord(
          [0],
          type,
          type == 24
              ? [
                  ...u16(0), 13, 0, 0, 0, 0, 0, //
                  0, 0, 0, 2, 0, 0, 0, 1, ...u16(7),
                  ...wireName('key.example'), 1, 2, 3, 4
                ]
              : [...wireName('hmac-sha256'), 1, 2, 3, 4],
          dnsClass: 255),
    ];
