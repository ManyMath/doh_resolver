/// Strict bounded TXT resolution through DNS over HTTPS JSON APIs.
library;

export 'package:doh_transport/doh_transport.dart'
    show
        DnsException,
        DnsInvalidNameException,
        DnsInvalidQueryException,
        DnsMalformedResponseException,
        DnsResponseTooLargeException,
        DnsQuestionMismatchException,
        DnsTransportException,
        DnsCancelledException,
        DnsTimeoutException,
        DnsOperation,
        DohHttpResponse,
        DohTransport,
        DnsRecord,
        DnsTxtRecord,
        DohWireTransport,
        normalizeDnsName,
        effectiveDnsTtl,
        isUsableDohEndpoint;

export 'src/dns.dart';
export 'src/resolver.dart';
