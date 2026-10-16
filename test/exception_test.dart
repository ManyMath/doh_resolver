import 'package:doh_resolver/doh_resolver.dart';
import 'package:doh_transport/doh_transport.dart' as transport;
import 'package:test/test.dart';

void main() {
  final transportCause = StateError('private resolver endpoint') as Object;
  const requestTimeout = transport.DohRequestTimeoutException('request timeout',
      timeout: Duration(seconds: 30));

  test('every resolver failure has the sealed package root', () {
    final failures = <DohResolverException>[
      const DohResolverInvalidNameException('invalid name'),
      const DohResolverMalformedResponseException('malformed'),
      const DohResolverResponseTooLargeException('large',
          kind: DohResolverLimitKind.responseBytes,
          maximum: 65536,
          actual: 65537),
      const DohResolverQuestionMismatchException('wrong question'),
      const DohResolverHttpStatusException('HTTP failure', statusCode: 503),
      DohResolverTransportException('transport failure', cause: transportCause),
      const DohResolverTransportTimeoutException('transport timeout',
          timeout: Duration(seconds: 30), cause: requestTimeout),
      const DohResolverLookupTimeoutException('lookup timeout',
          timeout: Duration(seconds: 12)),
      const DohResolverCancelledException('cancelled',
          source: DohResolverCancellationSource.caller),
      const DohResolverQueryFailedException('query failed', rcode: 3),
      const DohResolverAuthenticationUnavailableException('unauthenticated'),
      const DohResolverAliasLoopException('loop'),
      const DohResolverAliasAmbiguousException('ambiguous'),
      const DohResolverAliasTooLongException('too long'),
    ];

    expect(failures, everyElement(isA<DohResolverException>()));
    expect(failures.map((failure) => failure.runtimeType).toSet(),
        hasLength(failures.length));
  });

  test('structured fields preserve protocol and deadline distinctions', () {
    const rcode = DohResolverQueryFailedException('failed', rcode: 2);
    const http = DohResolverHttpStatusException('failed', statusCode: 429);
    const limit = DohResolverResponseTooLargeException('large',
        kind: DohResolverLimitKind.answers, maximum: 64, actual: 65);
    const lookupTimeout = DohResolverLookupTimeoutException('late',
        timeout: Duration(seconds: 12));

    expect(rcode.rcode, 2);
    expect(http.statusCode, 429);
    expect(limit.kind, DohResolverLimitKind.answers);
    expect(limit.maximum, 64);
    expect(limit.actual, 65);
    expect(lookupTimeout.timeout, const Duration(seconds: 12));
    expect(
        rcode.toString(), 'DohResolverQueryFailedException(rcode: 2): failed');
    expect(http.toString(),
        'DohResolverHttpStatusException(statusCode: 429): failed');
  });

  test('retained causes are not rendered by toString', () {
    final failure = DohResolverTransportException('transport failed',
        cause: transportCause);

    expect(failure.cause, same(transportCause));
    expect(
        failure.toString(), 'DohResolverTransportException: transport failed');
    expect(failure.toString(), isNot(contains('private resolver endpoint')));
  });

  test('any leaf retains an arbitrary cause and its stack trace', () {
    final stack = StackTrace.current;
    final failures = <DohResolverException>[
      DohResolverInvalidNameException('x', cause: 7, causeStackTrace: stack),
      DohResolverHttpStatusException('x',
          statusCode: 500, cause: 7, causeStackTrace: stack),
      DohResolverCancelledException('x',
          source: DohResolverCancellationSource.transport,
          cause: 7,
          causeStackTrace: stack),
      DohResolverAliasLoopException('x', cause: 7, causeStackTrace: stack),
    ];
    for (final failure in failures) {
      expect(failure.cause, 7);
      expect(failure.causeStackTrace, same(stack));
      expect(failure.toString(), isNot(contains('7')));
    }
    expect(const DohResolverTransportException('x').cause, isNull);
  });
}
