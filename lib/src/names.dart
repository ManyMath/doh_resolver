import 'dart:math';

import 'dns.dart';

final _label = RegExp(r'^[a-z0-9_-]+$');

/// Lower-cases [name], strips one trailing dot, and validates an ASCII DNS
/// name of at most 253 octets with labels of letters, digits, `_` or `-`.
String normalizeDnsName(String name) {
  if (name.codeUnits.any((c) => c > 127)) {
    throw const DohResolverInvalidNameException('Use ASCII DNS names');
  }
  final value = (name.endsWith('.') ? name.substring(0, name.length - 1) : name)
      .toLowerCase();
  if (value.isEmpty ||
      value.length > 253 ||
      !value.split('.').every((label) =>
          label.isNotEmpty && label.length <= 63 && _label.hasMatch(label))) {
    throw const DohResolverInvalidNameException('Invalid ASCII DNS name');
  }
  return value;
}

/// The remaining lifetime of a received DNS [ttl], in seconds: zero when its
/// most significant bit is set, reduced by HTTP cache [age], and never
/// negative.
int effectiveDnsTtl(int ttl, {Duration age = Duration.zero}) {
  if (ttl < 0 || ttl > 0xffffffff) throw ArgumentError.value(ttl, 'ttl');
  if (age < Duration.zero) throw ArgumentError.value(age, 'age');
  return max(0, (ttl > 0x7fffffff ? 0 : ttl) - age.inSeconds);
}

/// Whether [uri] is an HTTPS endpoint without credentials or fragment, with a
/// host and a port that parses and fits 1-65535.
bool isUsableEndpoint(Uri uri) {
  if (uri.scheme != 'https' ||
      uri.host.isEmpty ||
      uri.userInfo.isNotEmpty ||
      uri.hasFragment) {
    return false;
  }
  try {
    return uri.port >= 1 && uri.port <= 65535;
  } on FormatException {
    return false;
  }
}
