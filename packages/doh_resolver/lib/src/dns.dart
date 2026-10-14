import 'dart:convert';

import 'package:doh_transport/doh_transport.dart';

/// The resolver answered with a non-zero DNS RCODE, such as 3 (NXDOMAIN).
final class DnsQueryFailedException extends DnsException {
  final int rcode;
  const DnsQueryFailedException(super.message, {required this.rcode});
}

/// A response that was not marked authenticated, had checking disabled, or
/// was truncated, so it carries no resolver DNSSEC assertion.
final class DnsAuthenticationUnavailableException extends DnsException {
  const DnsAuthenticationUnavailableException(super.message);
}

/// The answer's CNAME chain could not be followed to a single owner.
sealed class DnsAliasException extends DnsException {
  const DnsAliasException(super.message);
}

/// A CNAME chain that revisits an owner.
final class DnsAliasLoopException extends DnsAliasException {
  const DnsAliasLoopException(super.message);
}

/// An owner with several CNAMEs, or with both a CNAME and TXT records.
final class DnsAliasAmbiguousException extends DnsAliasException {
  const DnsAliasAmbiguousException(super.message);
}

/// A CNAME chain longer than the configured owner limit.
final class DnsAliasTooLongException extends DnsAliasException {
  const DnsAliasTooLongException(super.message);
}

/// A question from a JSON DNS response.
class DnsQuestion {
  final String name;
  final int type;
  const DnsQuestion(this.name, this.type);
}

/// TXT records from an AD-flagged resolver response. An empty [records] list is
/// a NODATA answer the resolver asserts is authenticated.
final class ResolverAssertedTxtResult {
  final String question;
  final String canonicalName;
  final Uri resolver;
  final List<DnsTxtRecord> records;
  final List<DnsRecord> aliases;
  final DnsResponse? response;
  ResolverAssertedTxtResult._(this.question, this.canonicalName, this.resolver,
      List<DnsTxtRecord> records, List<DnsRecord> aliases, this.response)
      : records = List.unmodifiable(records),
        aliases = List.unmodifiable(aliases);

  /// How long the answer may be cached, in seconds: the smallest TTL over
  /// [records] and the [aliases] leading to them. Null for a NODATA answer.
  int? get ttl {
    if (records.isEmpty) return null;
    return [
      for (final record in records) record.ttl,
      for (final alias in aliases) alias.ttl,
    ].reduce((a, b) => a < b ? a : b);
  }
}

@Deprecated('Use ResolverAssertedTxtResult')
typedef AuthenticatedTxtResult = ResolverAssertedTxtResult;

/// A bounded, validated JSON DNS response from [resolver].
class DnsResponse {
  final Uri resolver;
  final int status;
  final bool? authenticatedData;
  final bool? checkingDisabled;
  final bool? truncated;
  final List<DnsQuestion> questions;
  final List<DnsRecord> answers;

  /// The HTTP cache age already subtracted from the answer TTLs.
  final Duration age;
  DnsResponse._(
      this.resolver,
      this.status,
      this.authenticatedData,
      this.checkingDisabled,
      this.truncated,
      this.questions,
      this.answers,
      this.age);

  /// Validates [json] from a DoH JSON API. Answer TTLs are reduced by the
  /// response's HTTP cache [age] and normalized by [effectiveDnsTtl]. The
  /// `Question` and `Answer` lists are each bounded by [maxAnswers].
  factory DnsResponse.fromJson(Object? json,
      {required Uri resolver,
      int maxAnswers = 64,
      Duration age = Duration.zero}) {
    if (age < Duration.zero) throw ArgumentError.value(age, 'age');
    if (maxAnswers < 0) throw ArgumentError.value(maxAnswers, 'maxAnswers');
    const malformed =
        DnsMalformedResponseException('Invalid DNS JSON response');
    if (json is! Map<String, dynamic>) throw malformed;
    final status = json['Status'];
    if (status is! int || status < 0 || status > 0xffff) throw malformed;
    bool? flag(String name) {
      final value = json[name];
      if (value != null && value is! bool) throw malformed;
      return value as bool?;
    }

    final rawQuestions = json['Question'];
    final rawAnswers = json['Answer'] ?? <Object>[];
    if (rawQuestions is! List || rawAnswers is! List) throw malformed;
    if (rawQuestions.length > maxAnswers) {
      throw const DnsResponseTooLargeException('Too many DNS questions');
    }
    if (rawAnswers.length > maxAnswers) {
      throw const DnsResponseTooLargeException('Too many DNS answers');
    }
    String name(Object? input) {
      if (input is! String) throw malformed;
      try {
        return normalizeDnsName(input);
      } on DnsException {
        throw malformed;
      }
    }

    final questions = <DnsQuestion>[];
    for (final q in rawQuestions) {
      if (q is! Map ||
          q['type'] is! int ||
          (q['type'] as int) < 0 ||
          (q['type'] as int) > 0xffff) {
        throw malformed;
      }
      questions.add(DnsQuestion(name(q['name']), q['type'] as int));
    }
    final answers = <DnsRecord>[];
    for (final a in rawAnswers) {
      if (a is! Map ||
          a['type'] is! int ||
          a['TTL'] is! int ||
          (a['TTL'] as int) < 0 ||
          (a['TTL'] as int) > 0xffffffff ||
          (a['type'] as int) < 0 ||
          (a['type'] as int) > 0xffff ||
          a['data'] is! String) {
        throw malformed;
      }
      answers.add(DnsRecord(
          name: name(a['name']),
          type: a['type'] as int,
          ttl: effectiveDnsTtl(a['TTL'] as int, age: age),
          data: a['data'] as String));
    }
    return DnsResponse._(resolver, status, flag('AD'), flag('CD'), flag('TC'),
        List.unmodifiable(questions), List.unmodifiable(answers), age);
  }

  /// The TXT records answering [domain], following at most [maxOwnerVisits]
  /// owners through CNAMEs. Requires a successful, AD-flagged, untruncated
  /// response with checking enabled and a single matching TXT question.
  ResolverAssertedTxtResult authenticatedTxt(String domain,
      {required DnsTxtFormat txtFormat, int maxOwnerVisits = 8}) {
    domain = normalizeDnsName(domain);
    if (status != 0) {
      throw DnsQueryFailedException('DNS query failed', rcode: status);
    }
    if (authenticatedData != true ||
        checkingDisabled != false ||
        truncated != false) {
      throw const DnsAuthenticationUnavailableException(
          'Authenticated complete DNS response required');
    }
    if (questions.length != 1 ||
        questions.single.type != 16 ||
        questions.single.name != domain) {
      throw const DnsQuestionMismatchException('DNS question mismatch');
    }
    var owner = domain;
    final seen = <String>{};
    final aliases = <DnsRecord>[];
    for (var visit = 0; visit < maxOwnerVisits; visit++) {
      if (!seen.add(owner)) {
        throw const DnsAliasLoopException('CNAME loop');
      }
      final records = answers.where((record) => record.name == owner);
      final cnames = records.where((record) => record.type == 5).toList();
      final txt = records.where((record) => record.type == 16).toList();
      if (cnames.isEmpty) {
        return ResolverAssertedTxtResult._(
            domain,
            owner,
            resolver,
            txt
                .map((r) => DnsTxtRecord(
                    name: owner,
                    ttl: r.ttl,
                    bytes: decodeDnsTxtBytes(r.data, txtFormat)))
                .toList(),
            aliases,
            this);
      }
      if (cnames.length != 1 || txt.isNotEmpty) {
        throw const DnsAliasAmbiguousException('Ambiguous CNAME owner');
      }
      aliases.add(cnames.single);
      try {
        owner = normalizeDnsName(cnames.single.data);
      } on DnsException {
        throw const DnsMalformedResponseException('Invalid CNAME target');
      }
    }
    throw const DnsAliasTooLongException('CNAME chain exceeds owner limit');
  }
}

/// How a JSON DoH resolver writes TXT `data`; set per endpoint.
enum DnsTxtFormat {
  /// Quoted RFC 1035 character-strings separated by spaces, with `\DDD`
  /// decimal and `\X` literal escapes, as Cloudflare returns them.
  quoted,

  /// The character-strings concatenated verbatim, without quoting or
  /// escaping, as Google returns them.
  raw,
}

/// Decodes JSON TXT `data` in [format] to the record's octets.
List<int> decodeDnsTxtBytes(String value, DnsTxtFormat format,
    {int maxPresentationLength = 8192}) {
  if (value.length > maxPresentationLength) {
    throw const DnsResponseTooLargeException('TXT presentation exceeds limit');
  }
  const malformed = DnsMalformedResponseException('Malformed TXT presentation');
  // utf8.encode would silently turn these into U+FFFD, altering the octets.
  for (var i = 0; i < value.length; i++) {
    final unit = value.codeUnitAt(i);
    if (unit & 0xfc00 == 0xdc00) throw malformed;
    if (unit & 0xfc00 == 0xd800) {
      if (i + 1 == value.length || value.codeUnitAt(i + 1) & 0xfc00 != 0xdc00) {
        throw malformed;
      }
      i++;
    }
  }
  if (format == DnsTxtFormat.raw) return utf8.encode(value);
  final bytes = <int>[];
  var strings = 0;
  var i = 0;
  while (i < value.length) {
    while (i < value.length && value[i] == ' ') {
      i++;
    }
    if (i == value.length) break;
    if (value[i++] != '"') throw malformed;
    var closed = false;
    while (i < value.length) {
      if (value[i] == '"') {
        i++;
        closed = true;
        break;
      }
      if (value[i] == '\\') {
        i++;
        if (i == value.length) throw malformed;
        bool digit(int at) =>
            at < value.length &&
            value.codeUnitAt(at) >= 0x30 &&
            value.codeUnitAt(at) <= 0x39;
        if (digit(i)) {
          if (!digit(i + 1) || !digit(i + 2)) throw malformed;
          final octet = int.parse(value.substring(i, i + 3));
          if (octet > 255) throw malformed;
          bytes.add(octet);
          i += 3;
        } else {
          final pair = value.codeUnitAt(i) & 0xfc00 == 0xd800 &&
              i + 1 < value.length &&
              value.codeUnitAt(i + 1) & 0xfc00 == 0xdc00;
          final end = i + (pair ? 2 : 1);
          bytes.addAll(utf8.encode(value.substring(i, end)));
          i = end;
        }
      } else {
        final start = i;
        while (i < value.length && value[i] != '"' && value[i] != '\\') {
          i++;
        }
        bytes.addAll(utf8.encode(value.substring(start, i)));
      }
    }
    if (!closed) throw malformed;
    strings++;
  }
  // A TXT record holds at least one character-string, though it may be "".
  if (strings == 0) throw malformed;
  return bytes;
}
