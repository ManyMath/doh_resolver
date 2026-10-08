import 'package:doh_resolver/doh_resolver_io.dart';

Future<void> main(List<String> arguments) async {
  if (arguments.length != 1) {
    print('Usage: dart run example/doh_resolver_example.dart DOMAIN');
    return;
  }
  final transport = IoDohTransport();
  try {
    final resolver = DohResolver(transport: transport);
    try {
      final result = await resolver.lookupTxt(arguments.single);
      print('Asserted by ${result.resolver} (${result.authentication.name})');
      for (final record in result.records) {
        print('${record.name} TTL=${record.ttl}: ${record.text}');
      }
    } on DnsException catch (error) {
      print('Lookup rejected: ${error.code.name}');
    }
  } finally {
    await transport.close();
  }
}
