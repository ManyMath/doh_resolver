## 0.0.1

- Initial release.
- `DohResolver`: bounded JSON TXT lookups that accept only resolver-asserted,
  untruncated, checking-enabled answers to the exact question, following CNAME
  chains strictly. JSON TXT data is decoded per provider through `DnsTxtFormat`,
  defaulting for Google and Cloudflare hosts.
- Wire-format helpers: `validateDnsWireResponse` for strict framing and
  query/response binding, `padDnsWireQuery` for RFC 8467 padding, and
  `adjustDnsWireTtls` for cache-ready TTLs.
- TTLs honour RFC 2181 (high-bit TTLs are zero) and RFC 8484 HTTP `Age`, also
  exposed as `effectiveDnsTtl`.
- `IoDohTransport`: direct or SOCKS5 HTTPS through `socks_socket` ^2.0.0, with
  certificate verification, no redirects or proxy fallback, bounded bodies,
  deadlines, concurrency and queueing, and `close()`.
- Wire connection reuse per origin with transport-owned transaction IDs, so ID 0
  queries reuse connections while stale replies stay detectable. Signed queries,
  and exchanges started with `preserveMessage`, keep their exact bytes. Reuse is
  off by default when a proxy is set.
- Every failure is a subtype of the sealed `DnsException`, delivered through
  `DnsOperation.result`; starting an operation never throws.
