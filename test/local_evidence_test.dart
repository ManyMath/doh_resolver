import 'package:doh_resolver/doh_resolver.dart';
import 'package:test/test.dart';

void main() {
  final endpoint = Uri.https('resolver.example', '/dns-query');
  final issuer = DnsValidationIssuer('test validator');
  final txt = DnsTxtRecord(name: 'bob.example', ttl: 60, bytes: [65]);
  final cname =
      DnsRecord(name: 'alice.example', type: 5, ttl: 60, data: 'bob.example');

  test('local evidence preserves provenance without inventing remote flags',
      () {
    final result = issuer.issueTxt(
        question: 'alice.example',
        canonicalName: 'bob.example',
        resolver: endpoint,
        records: [txt],
        aliases: [cname]);
    expect(result.authentication, DnsAuthentication.locallyValidated);
    expect(result.validator, same(issuer.validator));
    expect(result.response, isNull);
    expect(() => result.records.clear(), throwsUnsupportedError);
  });

  test('local evidence rejects broken owner binding', () {
    for (final aliases in <List<DnsRecord>>[
      [],
      [DnsRecord(name: 'other.example', type: 5, ttl: 60, data: 'bob.example')]
    ]) {
      expect(
          () => issuer.issueTxt(
              question: 'alice.example',
              canonicalName: 'bob.example',
              resolver: endpoint,
              records: [txt],
              aliases: aliases),
          throwsA(isA<DnsException>()));
    }
    expect(
        () => issuer.issueTxt(
            question: 'alice.example',
            canonicalName: 'alice.example',
            resolver: endpoint,
            records: [txt]),
        throwsA(isA<DnsException>()));
  });

  test('validator identity cannot be claimed by another issuer', () {
    final other = DnsValidationIssuer('test validator');
    final forged = other.issueTxt(
        question: 'bob.example',
        canonicalName: 'bob.example',
        resolver: endpoint,
        records: [txt]);
    expect(forged.authentication, DnsAuthentication.locallyValidated);
    expect(identical(forged.validator, issuer.validator), isFalse);
    expect(other.validator.name, issuer.validator.name);
  });

  test('issued evidence snapshots caller records', () {
    final bytes = [65];
    final result = issuer.issueTxt(
        question: 'Alice.Example.',
        canonicalName: 'bob.example',
        resolver: endpoint,
        records: [DnsTxtRecord(name: 'BOB.example', ttl: 60, bytes: bytes)],
        aliases: [cname]);
    bytes[0] = 66;
    expect(result.question, 'alice.example');
    expect(result.records.single.name, 'bob.example');
    expect(result.records.single.text, 'A');
    expect(result.aliases.single.name, 'alice.example');
  });

  test('resolver-asserted results name no local validator', () {
    final response = DnsResponse.fromJson({
      'Status': 0,
      'AD': true,
      'CD': false,
      'TC': false,
      'Question': [
        {'name': 'bob.example.', 'type': 16}
      ],
      'Answer': [
        {'name': 'bob.example.', 'type': 16, 'TTL': 60, 'data': 'A'}
      ],
    }, resolver: endpoint);
    final result = response.authenticatedTxt('bob.example');
    expect(result.authentication, DnsAuthentication.resolverAsserted);
    expect(result.validator, isNull);
  });
}
