import 'dart:io';

import 'package:doh_resolver/doh_resolver_io.dart';
import 'package:test/test.dart';

final skip = Platform.environment['DOH_LIVE_TESTS'] == '1'
    ? null
    : 'Set DOH_LIVE_TESTS=1 to query public resolvers';

void main() {
  for (final endpoint in [
    Uri.https('dns.google', '/resolve'),
    Uri.https('cloudflare-dns.com', '/dns-query'),
  ]) {
    test('${endpoint.host} JSON resolver-asserted TXT', () async {
      final transport = IoDohTransport();
      addTearDown(transport.close);
      final result = await DohResolver(transport: transport, endpoint: endpoint)
          .lookupTxt('getmonero.org');
      expect(result.records, isNotEmpty);
    }, skip: skip);
  }

  // The DKIM key is a CNAME to a TXT record of several character-strings,
  // so it covers chunk joining in both provider encodings.
  for (final domain in ['getmonero.org', 'protonmail._domainkey.proton.me']) {
    test('Google raw and Cloudflare quoted TXT decode $domain identically',
        () async {
      Future<Set<String>> texts(Uri endpoint) async {
        final transport = IoDohTransport();
        addTearDown(transport.close);
        return {
          for (final record
              in (await DohResolver(transport: transport, endpoint: endpoint)
                      .lookupTxt(domain))
                  .records)
            record.text
        };
      }

      final google = await texts(Uri.https('dns.google', '/resolve'));
      expect(
          google, await texts(Uri.https('cloudflare-dns.com', '/dns-query')));
      if (domain.contains('_domainkey')) {
        expect(google.single.length, greaterThan(255));
      }
    }, skip: skip);
  }
}
