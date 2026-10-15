import 'dart:collection';

import 'package:doh_resolver/doh_resolver.dart';
import 'package:test/test.dart';

import 'support/dns_wire.dart';

// Count byte reads instead of timing: expose quadratic decompression reliably.
class CountingBytes extends ListBase<int> {
  final List<int> bytes;
  int reads = 0;
  CountingBytes(this.bytes);
  @override
  int get length => bytes.length;
  @override
  set length(int value) => throw UnsupportedError('immutable');
  @override
  int operator [](int index) {
    reads++;
    return bytes[index];
  }

  @override
  void operator []=(int index, int value) =>
      throw UnsupportedError('immutable');
}

void main() {
  test('backward pointer chains take bounded linear work', () {
    // DNS compression offsets are 14 bits. Build a chain entirely below 16 KiB,
    // then refer to its tail for the remainder of a near-maximum-size message.
    final records = <List<int>>[];
    var previous = 12;
    var offset = 12 + wireQuestion(wireName('alice.example')).length;
    for (var i = 0; i < 5000; i++) {
      final record =
          wireRecord([0xc0 | (previous >> 8), previous & 255], 99, []);
      records.add(record);
      if (offset < 16384) previous = offset;
      offset += record.length;
    }
    final response = CountingBytes(wireReply(answers: records));
    validateDnsWireResponse(wireQuery(), response);
    expect(response.reads, lessThan(response.length * 30));
  });
}
