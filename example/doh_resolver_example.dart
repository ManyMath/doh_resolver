import 'dart:async';
import 'dart:io';

import 'package:doh_resolver/doh_resolver.dart';

/// A minimal [DohResolverTransport] over `dart:io`: no redirects, a bounded
/// body read and a request timeout.
class HttpClientDohResolverTransport implements DohResolverTransport {
  HttpClientDohResolverTransport({this.timeout = const Duration(seconds: 10)});

  final Duration timeout;
  final _client = HttpClient();

  void close() => _client.close(force: true);

  @override
  DohResolverOperation<DohResolverResponse> start(Uri uri,
      {required int maxResponseBytes}) {
    final done = Completer<DohResolverResponse>();
    HttpClientRequest? request;
    void fail(DohResolverException error) {
      if (!done.isCompleted) done.completeError(error);
      request?.abort();
    }

    final timer = Timer(
        timeout,
        () => fail(DohResolverTransportTimeoutException('Request timed out',
            timeout: timeout)));
    () async {
      try {
        final current = request = await _client.getUrl(uri);
        if (done.isCompleted) return current.abort();
        current.followRedirects = false;
        current.headers.set(HttpHeaders.acceptHeader, 'application/dns-json');
        final response = await current.close();
        final body = <int>[];
        await for (final chunk in response) {
          body.addAll(chunk);
          if (body.length > maxResponseBytes) {
            return fail(DohResolverResponseTooLargeException(
                'Response too large',
                kind: DohResolverLimitKind.responseBytes,
                maximum: maxResponseBytes));
          }
        }
        final age =
            int.tryParse(response.headers.value(HttpHeaders.ageHeader) ?? '');
        if (!done.isCompleted) {
          done.complete(DohResolverResponse(response.statusCode, body,
              age: Duration(seconds: age != null && age > 0 ? age : 0)));
        }
      } catch (error, stack) {
        if (!done.isCompleted) {
          done.completeError(DohResolverTransportException('Request failed',
              cause: error, causeStackTrace: stack));
        }
      } finally {
        timer.cancel();
      }
    }();
    return DohResolverOperation(
        done.future,
        () => fail(const DohResolverCancelledException('Request cancelled',
            source: DohResolverCancellationSource.transport)));
  }
}

Future<void> main(List<String> arguments) async {
  if (arguments.length != 1) {
    print('Usage: dart run example/doh_resolver_example.dart DOMAIN');
    return;
  }
  final transport = HttpClientDohResolverTransport();
  try {
    final resolver = DohResolver(transport: transport);
    try {
      final result = await resolver.lookupTxt(arguments.single);
      print('Asserted by ${result.resolver}');
      for (final record in result.records) {
        print('${record.name} TTL=${record.ttl}: ${record.text}');
      }
    } on DohResolverException catch (error) {
      print('Lookup rejected: $error');
    }
  } finally {
    transport.close();
  }
}
