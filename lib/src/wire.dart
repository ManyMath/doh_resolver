import 'dart:typed_data';

import 'dns.dart';

const _malformed = DnsMalformedResponseException('Malformed DNS wire message');
const _mismatch =
    DnsQuestionMismatchException('DNS wire response does not match query');

/// This is framing only: it never makes the answer trustworthy.
void validateDnsWireResponse(List<int> query, List<int> response) {
  final sent = _parseOrNull(query);
  if (sent == null || sent.isResponse) {
    throw const DnsInvalidQueryException('Invalid DNS wire query');
  }
  final reply = _WireMessage.parse(response);
  if (!reply.isResponse) throw _malformed;
  if (reply.flags & 0x0200 != 0) {
    throw const DnsMalformedResponseException('Truncated DNS wire response');
  }
  if (reply.id != sent.id ||
      reply.opcode != sent.opcode ||
      reply.questions.length != sent.questions.length) {
    throw _mismatch;
  }
  for (var i = 0; i < sent.questions.length; i++) {
    if (!reply.questions[i].matches(sent.questions[i])) throw _mismatch;
  }
  if (reply.optVersion case final version? when version != 0) {
    throw _malformed;
  }
}

List<int> padDnsWireQuery(List<int> query, {int blockSize = 128}) {
  if (blockSize < 1 || blockSize > 512) {
    throw ArgumentError.value(blockSize, 'blockSize');
  }
  final message = _parseOrNull(query);
  if (message == null || message.isResponse) {
    throw const DnsInvalidQueryException('Invalid DNS wire query');
  }
  final rdlength = message.optRdlengthOffset;
  if (rdlength == null || !message.optIsLast || message.optHasPadding) {
    return List<int>.unmodifiable(query);
  }
  final padding = (blockSize - (query.length + 4) % blockSize) % blockSize;
  final length = query.length + 4 + padding;
  final optLength = (query[rdlength] << 8 | query[rdlength + 1]) + 4 + padding;
  if (length > 65535 || optLength > 65535) {
    return List<int>.unmodifiable(query);
  }
  final padded = Uint8List(length)
    ..setRange(0, query.length, query)
    ..[rdlength] = optLength >> 8
    ..[rdlength + 1] = optLength & 0xff
    ..[query.length] = 0
    ..[query.length + 1] = 12
    ..[query.length + 2] = padding >> 8
    ..[query.length + 3] = padding & 0xff;
  return List<int>.unmodifiable(padded);
}

List<int> checkedDnsWireQuery(List<int> query) {
  final message = _parseOrNull(query);
  if (message == null || message.isResponse) {
    throw const DnsInvalidQueryException('Invalid DNS wire query');
  }
  return List<int>.unmodifiable(query);
}

_WireMessage? _parseOrNull(List<int> bytes) {
  try {
    return _WireMessage.parse(bytes);
  } on DnsException {
    return null;
  }
}

class _Question {
  final List<int> name;
  final int type;
  final int dnsClass;
  _Question(this.name, this.type, this.dnsClass);

  bool matches(_Question other) {
    if (type != other.type ||
        dnsClass != other.dnsClass ||
        name.length != other.name.length) {
      return false;
    }
    for (var i = 0; i < name.length; i++) {
      if (name[i] != other.name[i]) return false;
    }
    return true;
  }
}

class _WireMessage {
  final List<int> data;
  final questions = <_Question>[];
  final _nameStarts = <int>{};
  int? optRdlengthOffset;
  int? optVersion;
  bool optIsLast = false;
  bool optHasPadding = false;
  int _offset = 12;

  _WireMessage._(this.data);

  int get id => _u16(0);
  int get flags => _u16(2);
  bool get isResponse => flags & 0x8000 != 0;
  int get opcode => flags >> 11 & 0xf;

  factory _WireMessage.parse(List<int> bytes) {
    if (bytes.length < 12 ||
        bytes.length > 65535 ||
        bytes.any((byte) => byte < 0 || byte > 255)) {
      throw _malformed;
    }
    final message = _WireMessage._(bytes);
    message._parse();
    return message;
  }

  int _u16(int offset) => data[offset] << 8 | data[offset + 1];

  void _need(int count) {
    if (_offset + count > data.length) throw _malformed;
  }

  void _parse() {
    final counts = [_u16(4), _u16(6), _u16(8), _u16(10)];
    for (var i = 0; i < counts[0]; i++) {
      final name = _name();
      _need(4);
      questions.add(_Question(name, _u16(_offset), _u16(_offset + 2)));
      _offset += 4;
    }
    for (var section = 1; section < 4; section++) {
      for (var i = 0; i < counts[section]; i++) {
        _record(additional: section == 3);
      }
    }
    if (_offset != data.length) throw _malformed;
  }

  void _record({required bool additional}) {
    final owner = _offset;
    _name();
    _need(10);
    final type = _u16(_offset);
    final rdlength = _u16(_offset + 8);
    final start = _offset + 10;
    final end = start + rdlength;
    if (end > data.length) throw _malformed;
    if (type == 41) {
      if (!additional || optRdlengthOffset != null || data[owner] != 0) {
        throw _malformed;
      }
      optRdlengthOffset = _offset + 8;
      optVersion = data[_offset + 5];
      for (var at = start; at < end;) {
        if (at + 4 > end) throw _malformed;
        if (_u16(at) == 12) optHasPadding = true;
        at += 4 + _u16(at + 2);
        if (at > end) throw _malformed;
      }
    }
    _offset = start;
    switch (type) {
      case 2 || 3 || 4 || 5 || 7 || 8 || 9 || 12:
        _name(limit: end);
      case 14:
        _name(limit: end);
        _name(limit: end);
      case 15 || 18 || 21:
        _skip(2, end);
        _name(limit: end);
      case 17:
        _name(limit: end);
        _name(limit: end);
      case 6:
        _name(limit: end);
        _name(limit: end);
        _skip(20, end);
      case 24:
        _skip(18, end);
        _name(limit: end);
        if (_offset >= end) throw _malformed;
      case 26:
        _skip(2, end);
        _name(limit: end);
        _name(limit: end);
      case 30:
        _name(limit: end);
        _skip(4, end);
      case 33:
        _skip(6, end);
        _name(limit: end);
      case 35:
        _skip(4, end);
        _characterString(end);
        _characterString(end);
        _characterString(end);
        _name(limit: end);
      case 36:
        _skip(2, end);
        _name(limit: end, compressed: false);
      case 38:
        _skip(1, end);
        final prefixLength = data[_offset - 1];
        if (prefixLength > 128) throw _malformed;
        _skip((128 - prefixLength + 7) ~/ 8, end);
        if (prefixLength != 0) {
          _name(limit: end, compressed: false);
        }
      case 39:
        _name(limit: end, compressed: false);
      case 46:
        _skip(18, end);
        _name(limit: end, compressed: false);
        if (_offset >= end) throw _malformed;
      case 47:
        _name(limit: end, compressed: false);
    }
    if (_offset > end ||
        ({
              2,
              3,
              4,
              5,
              6,
              7,
              8,
              9,
              12,
              14,
              15,
              17,
              18,
              21,
              26,
              33,
              35,
              36,
              38,
              39
            }.contains(type) &&
            _offset != end)) {
      throw _malformed;
    }
    _offset = end;
    optIsLast = type == 41;
  }

  void _skip(int count, int limit) {
    if (_offset + count > limit) throw _malformed;
    _offset += count;
  }

  void _characterString(int limit) {
    _skip(1, limit);
    _skip(data[_offset - 1], limit);
  }

  // Pointers must move strictly backwards past every earlier jump, so loops are impossible.
  List<int> _name({int? limit, bool compressed = true}) {
    final name = <int>[];
    var at = _offset;
    var bound = limit ?? data.length;
    var lowest = _offset;
    int? resume;
    while (true) {
      if (at >= bound) throw _malformed;
      _nameStarts.add(at);
      final length = data[at];
      if (length == 0) {
        name.add(0);
        if (name.length > 255) throw _malformed;
        _offset = resume ?? at + 1;
        return name;
      }
      switch (length & 0xc0) {
        case 0xc0:
          if (!compressed || at + 1 >= bound) throw _malformed;
          final target = (length & 0x3f) << 8 | data[at + 1];
          if (target < 12 ||
              target >= lowest ||
              !_nameStarts.contains(target)) {
            throw _malformed;
          }
          resume ??= at + 2;
          lowest = at = target;
          bound = data.length;
        case 0:
          if (at + 1 + length > bound) throw _malformed;
          name.add(length);
          for (var i = at + 1; i <= at + length; i++) {
            final c = data[i];
            name.add(c >= 0x41 && c <= 0x5a ? c + 32 : c);
          }
          if (name.length + 1 > 255) throw _malformed;
          at += 1 + length;
        default:
          throw _malformed;
      }
    }
  }
}
