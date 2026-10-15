import 'dart:io';

import 'package:test/test.dart';

void main() {
  test('the example compiles and prints usage without arguments', () async {
    final result = await Process.run(
        Platform.resolvedExecutable, ['example/doh_resolver_example.dart']);
    expect(result.stderr, isEmpty);
    expect(result.exitCode, 0);
    expect(result.stdout, startsWith('Usage: dart run '));
  }, timeout: const Timeout(Duration(minutes: 2)));
}
