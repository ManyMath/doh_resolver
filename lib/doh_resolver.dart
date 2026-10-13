/// Bounded DNS over HTTPS: JSON TXT resolution with explicit authentication
/// evidence, and RFC 8484 wire-format helpers. Platform-independent; use
/// `package:doh_resolver/doh_resolver_io.dart` for the `dart:io` transport.
library;

export 'src/dns.dart';
export 'src/resolver.dart';
export 'src/wire.dart'
    show adjustDnsWireTtls, padDnsWireQuery, validateDnsWireResponse;
