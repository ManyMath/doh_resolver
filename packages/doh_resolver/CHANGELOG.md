## 0.1.0 - unreleased

- Breaking: `DnsAuthentication`, `DnsValidator`, `DnsValidationIssuer` and `issueTxt` are removed; results record only the resolver's AD assertion.
- Breaking: the transport, wire helpers and IO implementation moved to `doh_transport`, now a dependency.
- Breaking: `DnsException` is `doh_transport`'s open base class, so exhaustive switches over it no longer compile.
- Breaking: `AuthenticatedTxtResult` is renamed `ResolverAssertedTxtResult`; the old name is a deprecated typedef for one release.
- `DnsResponse.fromJson` rejects an out-of-range `Status` and bounds `Question` by `maxAnswers`.
- `ResolverAssertedTxtResult.ttl` is the minimum TTL over the records and their CNAME chain.

## 0.0.1 - unreleased

- Initial JSON resolver: bounded TXT parsing, per-provider TXT decoding, strict CNAME traversal and resolver-asserted DNSSEC results.
