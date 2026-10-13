# doh_resolver

Bounded DNS over HTTPS for Dart: JSON TXT resolution with explicit
authentication evidence, RFC 8484 wire-format helpers, and a `dart:io`
transport for direct or SOCKS5 HTTPS.

```dart
import 'package:doh_resolver/doh_resolver_io.dart';

final transport = IoDohTransport();
try {
  final result = await DohResolver(transport: transport).lookupTxt('example.com');
  for (final record in result.records) {
    print('${record.ttl}s ${record.text}');
  }
} on DnsQueryFailedException catch (error) {
  print('DNS rcode ${error.rcode}');
} on DnsException catch (error) {
  print('Rejected: $error');
} finally {
  await transport.close();
}
```

## Trust model

`DohResolver` accepts an answer only when the resolver asserts it is
DNSSEC-authenticated: the AD flag is set, checking is enabled, the reply is not
truncated, and its single TXT question matches the requested name. The result's
`DnsAuthentication.resolverAsserted` evidence means you trust that resolver; it
is not local DNSSEC validation. Use a local validator, such as
`dnssec_resolver`, when the resolver itself must not choose the answer.

A local validator reports its results through a `DnsValidationIssuer`. Anyone
can construct an issuer, so `DnsAuthentication.locallyValidated` and the
validator's name prove nothing on their own. Keep your issuer private and check
its identity:

```dart
bool trusted(AuthenticatedTxtResult result) =>
    identical(result.validator, myIssuer.validator);
```

`validateDnsWireResponse` checks message framing and that a response answers
its query; it does not validate DNSSEC signatures or make answer data trusted.

## JSON providers

DoH JSON APIs are not standardized, and providers encode TXT data differently:
Google returns the text verbatim, Cloudflare returns quoted character-strings
with escapes. A value alone cannot reveal which form it is in, so
`DohResolver.txtFormat` is chosen per endpoint. Google and Cloudflare hosts get
the right `DnsTxtFormat` by default; any other endpoint must pass `txtFormat`.

Lookups send `edns_client_subnet=0.0.0.0/0`, which asks providers that
implement it, such as Google, not to forward client subnet data. Cloudflare
does not send client subnets by default. The query URL is padded to a multiple
of 128 characters to hide the name's length. Endpoint query parameters are
kept, including repeated ones, except those the resolver sets itself.

## Transport

`IoDohTransport` requires HTTPS, verifies the endpoint certificate, never
follows redirects, bounds response bodies and deadlines, and never falls back
from a configured SOCKS proxy to a direct connection. The proxy resolves
endpoint host names unless `proxyDestination` supplies an address; that
override applies to every endpoint used with the transport, while TLS still
verifies the requested host name.

- **Limits.** `maxConcurrentRequests` operations run at once and
  `maxQueuedRequests` wait; a full queue fails new operations with
  `DnsTransportException`.
- **Deadlines.** `requestTimeout` covers each operation, including time spent
  queued. `DohResolver.timeout` covers a whole lookup. Whichever is earlier
  applies. Connection timeouts are reported as `DnsTransportException`; only an
  operation's own deadline is `DnsTimeoutException`.
- **Connection reuse.** JSON requests never share connections. Wire queries to
  the same origin do, unless a `proxy` is set: lookups sharing a connection can
  be linked by the resolver, so proxied transports reuse only with
  `reuseConnections: true`. Pass it when the transport already lives for one
  lookup on its own isolated stream, as with `SocksCredentials.isolation`:
  those queries share a circuit anyway, and a wire lookup makes several
  requests, so each new Tor stream and TLS handshake is pure cost. The
  transport gives each exchange a random ID that
  is unique on its connection and restores the caller's ID in the response, so
  callers may send ID 0 as RFC 8484 recommends. SIG(0)- and TSIG-signed queries
  are sent byte-for-byte, because their signatures cover the header. Pass
  `preserveMessage: true` to `startWire` when you expect a signed response to
  an unsigned query: a SIG(0) response covers the request as sent, so the query
  is then sent unpadded with its own ID and the response returned untouched.
  Any malformed, cancelled, timed-out or failed exchange retires its
  connection.
- **Shutdown.** `close()` fails queued and running operations with
  `DnsCancelledException` and begins closing connections; socket teardown
  finishes asynchronously.
- **HTTP/1.1 only.** Dart's `HttpClient` does not speak HTTP/2, so concurrent
  operations use separate connections.

## Errors and cancellation

Every failure is a subtype of the sealed `DnsException`, so you can catch one
case, all CNAME failures through `DnsAliasException`, or switch over every case
exhaustively. `DnsQueryFailedException` carries the DNS `rcode`, and
`DnsTransportException` carries `httpStatus` for a non-200 response. The one
open subtype is `DnsAuthenticationUnavailableException`: a local validator
extends it to say why it found no secure answer, and an exhaustive switch
still sees that as authentication being unavailable.

Starting an operation never throws: invalid names, URIs and wire queries, a
closed transport and a full queue all complete `DnsOperation.result` with a
`DnsException`. `ArgumentError` is reserved for invalid constructor arguments.

`DnsOperation.cancel` fails an unfinished operation with
`DnsCancelledException`. It does not consume that error: like any `Future`, a
result nobody listens to reports its error as uncaught, so attach a handler or
call `.ignore()` on results you discard.

## TTLs

RFC 8484 requires DNS TTLs to be reduced by a response's HTTP `Age`, and RFC
2181 says a TTL with its high bit set means zero. `DohResolver` applies both to
JSON answers. Wire bodies keep the TTLs the resolver sent: pass them through
`adjustDnsWireTtls(body, age: response.age)` before caching, or apply
`effectiveDnsTtl` to TTLs you decode. Verify any SIG(0) or TSIG transaction
signature first, since adjusting TTLs changes the signed message.

## Development

Run every pre-merge check (format, analyze, tests, publish dry-run) on any
platform with `dart tool/check.dart`. Live resolver tests are skipped unless
`DOH_LIVE_TESTS=1` is set.
