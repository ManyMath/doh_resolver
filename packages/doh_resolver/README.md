# doh_resolver

TXT lookups through DNS-over-HTTPS JSON APIs that accept only answers the
resolver marks as DNSSEC-authenticated.

## Usage

```dart
import 'package:doh_resolver/doh_resolver_io.dart';

final transport = IoDohTransport();
try {
  final result =
      await DohResolver(transport: transport).lookupTxt('example.com');
  for (final record in result.records) {
    print(record.text);
  }
} on DnsQueryFailedException catch (error) {
  print('rcode ${error.rcode}');
} on DnsException catch (error) {
  print(error);
} finally {
  await transport.close();
}
```

## Trust model

The resolver performs the DNSSEC validation; this package does not. An answer
is accepted only when the response has rcode 0, `AD` set, `CD` and `TC` clear
and a single TXT question for the normalized name. `ResolverAssertedTxtResult`
records that assertion and nothing more: a resolver that lies controls the
result. The transport verifies the endpoint certificate. The resolver sees the
queried name and type and, without a proxy, your address. For local validation
use `dnssec_resolver`.

## Configuration

- `endpoint`: a JSON API URI, `https://dns.google/resolve` by default. Google
  and Cloudflare hosts select their `DnsTxtFormat`; any other endpoint must
  pass `txtFormat`.
- `timeout` 12 s for a whole lookup; the transport's own deadline also applies.
- `maxResponseBytes` 65536.
- Proxy, fixed destination, connection reuse and transport deadlines are
  `IoDohTransport` options; see `doh_transport`.

Lookups send `do=true`, `cd=false` and `edns_client_subnet=0.0.0.0/0`, and pad
the URL to a multiple of 128 characters. `startTxtLookup` returns a
cancellable `DnsOperation` and never throws; every failure is a `DnsException`.

## Development

This repository is a pub workspace; the package is `packages/doh_resolver`.
`doh_transport` is not on pub.dev yet: clone it beside this repository and add
a root `pubspec_overrides.yaml`:

```yaml
dependency_overrides:
  doh_transport:
    path: ../doh_transport
```

Then run `dart pub get` at the root and `dart tool/check.dart` from
`packages/doh_resolver`. Live resolver tests run with `DOH_LIVE_TESTS=1`.

## License

MIT; see `LICENSE`.
