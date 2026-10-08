## 0.0.1

- Initial release.
- Bounded JSON and wire-format DNS over HTTPS, including authenticated TXT resolution over direct or SOCKS HTTPS.
- Local-validation evidence issued by `DnsValidationIssuer.issueTxt`, carrying the issuing `DnsValidator`.
- Connection reuse within `IoDohTransport`, with exclusive per-request lanes, `close()`, `idleTimeout` and `reuseConnections`.
- SOCKS transport through `socks_socket` ^2.0.0.
