## 0.0.1 - unreleased

- Initial JSON resolver with bounded response parsing, provider-specific TXT
  decoding, strict CNAME traversal, resolver-asserted DNSSEC results, sealed
  named exceptions, and cache lifetimes derived from the answer and its CNAME
  chain.
- Transport port (`DohResolverTransport`, `DohResolverOperation`,
  `DohResolverResponse`); the package has no dependencies.
