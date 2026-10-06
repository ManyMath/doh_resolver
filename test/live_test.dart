import 'dart:io';

import 'package:doh_resolver/doh_resolver_io.dart';
import 'package:test/test.dart';

import 'support/dns_wire.dart';

final skip = Platform.environment['DOH_LIVE_TESTS'] == '1'
    ? null
    : 'Set DOH_LIVE_TESTS=1 to query public resolvers';

List<int> dnssecQuery(String name, int type) => [
      ...wireHeader(id: 0, flags: 0x0110, ar: 1),
      ...wireQuestion(wireName(name), type: type),
      ...wireOpt(options: [0, 8, 0, 4, 0, 1, 0, 0]),
    ];

void main() {
  final endpoints = [
    Uri.https('dns.google', '/dns-query'),
    Uri.https('cloudflare-dns.com', '/dns-query'),
  ];
  for (final endpoint in endpoints) {
    for (final (name, type) in [
      ('getmonero.org', 16),
      ('.', 48),
      ('no-such-label-8484.getmonero.org', 16),
    ]) {
      test('${endpoint.host} wire $name/$type', () async {
        final response = await IoDohTransport()
            .startWire(endpoint, dnssecQuery(name, type),
                maxResponseBytes: 65535)
            .result;
        expect(response.statusCode, 200);
      }, skip: skip);
    }
  }
  for (final endpoint in [
    Uri.https('dns.google', '/resolve'),
    Uri.https('cloudflare-dns.com', '/dns-query'),
  ]) {
    test('${endpoint.host} JSON resolver-asserted TXT', () async {
      final result =
          await DohResolver(transport: IoDohTransport(), endpoint: endpoint)
              .lookupTxt('getmonero.org');
      expect(result.authentication, DnsAuthentication.resolverAsserted);
      expect(result.records, isNotEmpty);
    }, skip: skip);
  }
}
