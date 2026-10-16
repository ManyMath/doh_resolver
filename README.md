# doh_resolver

TXT lookups through DNS-over-HTTPS JSON APIs that accept only answers the
resolver marks as DNSSEC-authenticated.

## Usage

`DohResolver` needs a `DohResolverTransport`, the port that sends one bounded
HTTPS GET. `example/doh_resolver_example.dart` has a `dart:io` implementation.

```dart
final transport = HttpClientDohResolverTransport();
try {
  final result =
      await DohResolver(transport: transport).lookupTxt('example.com');
  print('cache for ${result.ttl}s');
  for (final record in result.records) {
    print(record.text);
  }
} on DohResolverQueryFailedException catch (error) {
  print('rcode ${error.rcode}');
} on DohResolverException catch (error) {
  print(error);
} finally {
  transport.close();
}
```

## Trust model

The resolver performs the DNSSEC validation; this package does not. An answer
is accepted only when the response has rcode 0, `AD` set, `CD` and `TC` clear
and a single TXT question for the normalized name. `ResolverAssertedTxtResult`
records that assertion and nothing more: a resolver that lies controls the
result. The transport you supply must verify the endpoint certificate. The resolver sees the
queried name and type and, without a proxy, your address. For local validation
use `dnssec_resolver`.

## Configuration

- `endpoint`: a JSON API URI, `https://dns.google/resolve` by default. Google
  and Cloudflare hosts select their `DnsTxtFormat`; any other endpoint must
  pass `txtFormat`.
- `timeout` 12 s for a whole lookup; the transport's own deadline also applies.
- `maxResponseBytes` 65536.
- Proxying, connection reuse and the transport's own deadline belong to your
  `DohResolverTransport`.

Lookups send `do=true`, `cd=false` and `edns_client_subnet=0.0.0.0/0`, and pad
the URL to a multiple of 128 characters. `startTxtLookup` returns a
cancellable `DohResolverOperation` and never throws; every deliberate failure
is a named leaf of sealed `DohResolverException`, with RCODE, HTTP status, size
limits, deadlines and cancellation source as typed fields. Causes are retained
in `cause` and `causeStackTrace` but not printed.

## Transport contract

`DohResolverTransport.start(uri, maxResponseBytes: n)` returns a
`DohResolverOperation<DohResolverResponse>` (status, body, `Age`). It must not
throw: failures complete the operation with a `DohResolverException` of the
implementation's choosing (for example `DohResolverHttpStatusException` or
`DohResolverTransportTimeoutException`); any other error is wrapped as
`DohResolverTransportException`. `cancel` is idempotent, and the transport
enforces `maxResponseBytes` while reading.

## Development

Run `dart tool/check.dart` from the repository root. Live resolver tests run
with `DOH_LIVE_TESTS=1 dart test test/live_test.dart`.

## License

MIT; see `LICENSE`.
