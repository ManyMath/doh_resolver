/// Strict bounded TXT resolution through DNS over HTTPS JSON APIs.
library;

export 'package:doh_transport/doh_transport.dart'
    show DnsOperation, DohHttpResponse, DohTransport, DohWireTransport;

export 'src/dns.dart';
export 'src/resolver.dart';
