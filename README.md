# doh_resolver

Bounded JSON and wire-format DNS-over-HTTPS with direct and SOCKS transports.

## Trust model

`DohResolver.lookupTxt` accepts the HTTPS resolver's AD assertion only when the
reply is complete, checking is enabled, and its single TXT question matches the
requested name. The resulting `DnsAuthentication.resolverAsserted` evidence is
not local DNSSEC validation. Use a local validator such as `dnssec_resolver`
when the resolver itself must not choose the answer.

`validateDnsWireResponse` provides strict message framing and request/response
binding; it does not validate DNSSEC signatures or make answer data trusted.

## Transport lifecycle

`IoDohTransport` requires HTTPS, verifies the certificate for the endpoint
hostname, rejects redirects, bounds response bodies and deadlines, and never
falls back from an explicitly configured SOCKS proxy to a direct connection.
SOCKS hostnames are resolved by the proxy unless the caller explicitly supplies
a numeric `proxyDestination`.

Call `close()` when the transport is no longer needed. JSON connections are not
reused because JSON has no transaction identifier. Wire connections are reused
only for the same HTTPS origin. The transport gives each exchange a fresh
random transaction ID on the wire, unique on its connection, and restores the
caller's ID in the returned body, so callers may send ID 0 as RFC 8484
recommends. Queries signed with SIG(0) or TSIG are sent byte-for-byte with
their own ID, because the signature covers the header; that ID is likewise
never repeated on a connection. Reuse defaults to off when a `proxy` is set, because
queries sharing a connection can be linked by the resolver; pass
`reuseConnections: true` to opt in. Malformed, cancelled, timed-out, or failed exchanges retire the
connection. `maxConcurrentRequests` and `maxQueuedRequests` bound admitted
work; a full queue fails new operations with `DnsTransportException`.

## Errors

Every failure is a subtype of the sealed `DnsException`, so callers can catch
a specific case or switch over all of them exhaustively. `DnsQueryFailedException`
carries the DNS `rcode`; `DnsTransportException` carries `httpStatus` when the
resolver returned a non-200 response.

Starting an operation never throws. Invalid names, URIs and wire queries,
a closed transport, and a full queue all complete `DnsOperation.result` with
a `DnsException`. `ArgumentError` is reserved for invalid constructor
configuration.

## Cache age

RFC 8484 requires DNS TTLs to be reduced by the HTTP `Age` of a response.
`DohResolver` applies this to JSON answers, flooring TTLs at zero. Wire-format
bodies are returned unmodified; callers must subtract `DohHttpResponse.age`
from any TTL they decode.
