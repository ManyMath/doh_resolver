import 'dart:convert';
import 'dart:math';

/// Every failure this package reports. Switch over it exhaustively, or catch
/// a specific subtype.
sealed class DnsException implements Exception {
  final String message;
  const DnsException(this.message);
  @override
  String toString() => '$runtimeType: $message';
}

/// A name that is not an ASCII DNS name of at most 253 octets with
/// labels of letters, digits, `_` or `-`.
final class DnsInvalidNameException extends DnsException {
  const DnsInvalidNameException(super.message);
}

/// A caller-supplied wire query or request URI was unusable.
final class DnsInvalidQueryException extends DnsException {
  const DnsInvalidQueryException(super.message);
}

/// A response, or caller-supplied evidence, that does not parse or is
/// internally inconsistent.
final class DnsMalformedResponseException extends DnsException {
  const DnsMalformedResponseException(super.message);
}

/// A response that exceeded a configured size or count bound.
final class DnsResponseTooLargeException extends DnsException {
  const DnsResponseTooLargeException(super.message);
}

/// The resolver answered with a non-zero DNS RCODE, such as 3 (NXDOMAIN).
final class DnsQueryFailedException extends DnsException {
  final int rcode;
  const DnsQueryFailedException(super.message, {required this.rcode});
}

/// A response that was not marked authenticated, had checking disabled, or
/// was truncated, so it carries no resolver DNSSEC assertion.
///
/// Local validators may extend this to report why their own validation did
/// not establish a secure answer; `switch` over [DnsException] still treats
/// every such subtype as this case.
base class DnsAuthenticationUnavailableException extends DnsException {
  const DnsAuthenticationUnavailableException(super.message);
}

/// A response, or CNAME chain, that does not answer the question asked.
final class DnsQuestionMismatchException extends DnsException {
  const DnsQuestionMismatchException(super.message);
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

/// The HTTPS exchange failed; [httpStatus] is set when a non-200 status
/// was received.
final class DnsTransportException extends DnsException {
  final int? httpStatus;
  const DnsTransportException(super.message, {this.httpStatus});
}

/// An operation cancelled by its caller or by closing its transport.
final class DnsCancelledException extends DnsException {
  const DnsCancelledException(super.message);
}

/// An operation that reached its own deadline. Connection establishment
/// timeouts are reported as [DnsTransportException].
final class DnsTimeoutException extends DnsException {
  const DnsTimeoutException(super.message);
}

final _label = RegExp(r'^[a-z0-9_-]+$');

/// The remaining lifetime of a received DNS [ttl], in seconds: zero when its
/// most significant bit is set (RFC 2181 §8), reduced by the HTTP cache [age]
/// (RFC 8484 §5.1), and never negative.
int effectiveDnsTtl(int ttl, {Duration age = Duration.zero}) {
  if (ttl < 0 || ttl > 0xffffffff) throw ArgumentError.value(ttl, 'ttl');
  if (age < Duration.zero) throw ArgumentError.value(age, 'age');
  return max(0, (ttl > 0x7fffffff ? 0 : ttl) - age.inSeconds);
}

/// Lower-cases [name], strips one trailing dot, and checks it is a valid
/// ASCII DNS name; throws [DnsInvalidNameException] otherwise.
String normalizeDnsName(String name) {
  if (name.codeUnits.any((c) => c > 127)) {
    throw const DnsInvalidNameException("Use ASCII DNS names");
  }
  final value = (name.endsWith('.') ? name.substring(0, name.length - 1) : name)
      .toLowerCase();
  if (value.isEmpty ||
      value.length > 253 ||
      !value.split('.').every((label) =>
          label.isNotEmpty && label.length <= 63 && _label.hasMatch(label))) {
    throw const DnsInvalidNameException('Invalid ASCII DNS name');
  }
  return value;
}

/// A question from a JSON DNS response.
class DnsQuestion {
  final String name;
  final int type;
  const DnsQuestion(this.name, this.type);
}

/// A resource record from a JSON DNS response, in the resolver's
/// presentation format. Parsed records hold an [effectiveDnsTtl].
class DnsRecord {
  final String name;
  final int type;
  final int ttl;
  final String data;
  const DnsRecord(
      {required this.name,
      required this.type,
      required this.ttl,
      required this.data});
}

/// The octets of one TXT RRset member, with its character-strings joined.
class DnsTxtRecord {
  final String name;
  final int ttl;
  final List<int> bytes;
  DnsTxtRecord(
      {required this.name, required this.ttl, required List<int> bytes})
      : bytes = List.unmodifiable(bytes) {
    if (this.bytes.any((byte) => byte < 0 || byte > 255)) {
      throw ArgumentError.value(bytes, 'bytes', 'TXT data must be octets');
    }
  }

  /// [bytes] decoded as UTF-8; throws [DnsMalformedResponseException] if
  /// they are not valid UTF-8.
  String get text {
    try {
      return utf8.decode(bytes);
    } on FormatException {
      throw const DnsMalformedResponseException('TXT is not UTF-8');
    }
  }
}

/// Where an [AuthenticatedTxtResult]'s authenticity claim comes from.
///
/// [resolverAsserted] means the HTTPS resolver set the AD flag; trust rests on
/// that resolver. [locallyValidated] means some [DnsValidationIssuer] in this
/// process vouched for it, so also check [AuthenticatedTxtResult.validator].
enum DnsAuthentication { resolverAsserted, locallyValidated }

/// The identity of a [DnsValidationIssuer]. Compare it with [identical];
/// [name] is only a label and is not unique.
final class DnsValidator {
  final String name;
  DnsValidator._(this.name);

  @override
  String toString() => 'DnsValidator($name)';
}

/// Mints [DnsAuthentication.locallyValidated] results for a local DNSSEC
/// validator.
///
/// Anyone can construct an issuer, so `locallyValidated` alone proves nothing.
/// Keep your issuer private and accept a result only when
/// `identical(result.validator, myIssuer.validator)`.
final class DnsValidationIssuer {
  final DnsValidator validator;
  DnsValidationIssuer(String name) : validator = DnsValidator._(name) {
    if (name.isEmpty) throw ArgumentError.value(name, 'name');
  }

  // Call only after signatures are verified; this checks owner binding.
  /// Issues evidence for [records] at [canonicalName], reached from
  /// [question] through [aliases]. Call only after verifying the signatures;
  /// this checks owner binding and bounds, not cryptography.
  AuthenticatedTxtResult issueTxt({
    required String question,
    required String canonicalName,
    required Uri resolver,
    required List<DnsTxtRecord> records,
    List<DnsRecord> aliases = const [],
  }) {
    question = normalizeDnsName(question);
    canonicalName = normalizeDnsName(canonicalName);
    if (records.isEmpty ||
        records.length > 64 ||
        aliases.length > 7 ||
        records.any((r) =>
            normalizeDnsName(r.name) != canonicalName ||
            r.ttl < 0 ||
            r.ttl > 0xffffffff)) {
      throw const DnsMalformedResponseException('Invalid validated TXT result');
    }
    var owner = question;
    final seen = <String>{owner};
    final chain = <DnsRecord>[];
    for (final alias in aliases) {
      if (alias.type != 5 ||
          normalizeDnsName(alias.name) != owner ||
          alias.ttl < 0 ||
          alias.ttl > 0xffffffff) {
        throw const DnsMalformedResponseException(
            'Invalid validated CNAME chain');
      }
      chain.add(DnsRecord(
          name: owner,
          type: 5,
          ttl: effectiveDnsTtl(alias.ttl),
          data: alias.data));
      owner = normalizeDnsName(alias.data);
      if (!seen.add(owner)) {
        throw const DnsAliasLoopException('CNAME loop');
      }
    }
    if (owner != canonicalName) {
      throw const DnsQuestionMismatchException(
          'CNAME chain does not reach TXT owner');
    }
    return AuthenticatedTxtResult._(
        question,
        canonicalName,
        resolver,
        [
          for (final r in records)
            DnsTxtRecord(
                name: canonicalName,
                ttl: effectiveDnsTtl(r.ttl),
                bytes: r.bytes)
        ],
        chain,
        null,
        DnsAuthentication.locallyValidated,
        validator);
  }
}

/// TXT records whose authenticity is attested by [authentication].
///
/// Only this package can create one: from an AD-flagged resolver response, or
/// through a [DnsValidationIssuer]. An empty [records] list is an
/// authenticated NODATA answer.
final class AuthenticatedTxtResult {
  final String question;
  final String canonicalName;
  final Uri resolver;
  final List<DnsTxtRecord> records;
  final List<DnsRecord> aliases;
  final DnsResponse? response;
  final DnsAuthentication authentication;
  final DnsValidator? validator;
  AuthenticatedTxtResult._(this.question, this.canonicalName, this.resolver,
      List<DnsTxtRecord> records, List<DnsRecord> aliases, this.response,
      [this.authentication = DnsAuthentication.resolverAsserted,
      this.validator])
      : records = List.unmodifiable(records),
        aliases = List.unmodifiable(aliases);
}

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
  /// response's HTTP cache [age] and normalized by [effectiveDnsTtl].
  factory DnsResponse.fromJson(Object? json,
      {required Uri resolver,
      int maxAnswers = 64,
      Duration age = Duration.zero}) {
    if (age < Duration.zero) throw ArgumentError.value(age, 'age');
    const malformed =
        DnsMalformedResponseException('Invalid DNS JSON response');
    if (json is! Map<String, dynamic> || json['Status'] is! int) {
      throw malformed;
    }
    bool? flag(String name) {
      final value = json[name];
      if (value != null && value is! bool) throw malformed;
      return value as bool?;
    }

    final rawQuestions = json['Question'];
    final rawAnswers = json['Answer'] ?? <Object>[];
    if (rawQuestions is! List ||
        rawQuestions.length > 64 ||
        rawAnswers is! List) {
      throw malformed;
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
    return DnsResponse._(
        resolver,
        json['Status'] as int,
        flag('AD'),
        flag('CD'),
        flag('TC'),
        List.unmodifiable(questions),
        List.unmodifiable(answers),
        age);
  }

  /// The TXT records answering [domain], following at most [maxOwnerVisits]
  /// owners through CNAMEs. Requires a successful, AD-flagged, untruncated
  /// response with checking enabled and a single matching TXT question.
  AuthenticatedTxtResult authenticatedTxt(String domain,
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
        return AuthenticatedTxtResult._(
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

/// How a JSON DoH resolver writes TXT `data`. Providers differ and a value
/// alone cannot reveal which form it is in, so the format is set per endpoint.
enum DnsTxtFormat {
  /// Quoted RFC 1035 character-strings separated by spaces, with `\DDD`
  /// decimal and `\X` literal escapes, as Cloudflare returns them.
  quoted,

  /// The character-strings concatenated verbatim, without quoting or
  /// escaping, as Google returns them.
  raw,
}

/// Decodes JSON TXT `data` in [format] to the record's octets. DNS decimal
/// escapes encode octets, so UTF-8 is decoded only after chunks are joined.
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
