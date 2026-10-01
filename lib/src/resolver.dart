import 'dart:async';
import 'dart:convert';
import 'dns.dart';

class DnsOperation<T> {
  final Future<T> result;
  final void Function() cancel;
  const DnsOperation(this.result, this.cancel);
}

class DohHttpResponse {
  final int statusCode;
  final List<int> body;
  DohHttpResponse(this.statusCode, List<int> body)
      : body = List.unmodifiable(body);
}

abstract interface class DohTransport {
  DnsOperation<DohHttpResponse> start(Uri uri, {required int maxResponseBytes});
}

class DohResolver {
  final DohTransport transport;
  final Uri endpoint;
  final Duration timeout;
  final int maxResponseBytes;
  DohResolver(
      {required this.transport,
      Uri? endpoint,
      this.timeout = const Duration(seconds: 12),
      this.maxResponseBytes = 65536})
      : endpoint = endpoint ?? Uri.https('dns.google', '/resolve') {
    if (this.endpoint.scheme != 'https' ||
        this.endpoint.host.isEmpty ||
        this.endpoint.userInfo.isNotEmpty ||
        this.endpoint.hasFragment) {
      throw ArgumentError(
          'A credential-free HTTPS resolver endpoint is required');
    }
    if (timeout <= Duration.zero || maxResponseBytes < 1) {
      throw ArgumentError('Invalid query limits');
    }
  }

  Future<AuthenticatedTxtResult> lookupTxt(String domain) =>
      startTxtLookup(domain).result;

  DnsOperation<AuthenticatedTxtResult> startTxtLookup(String domain) {
    domain = normalizeDnsName(domain);
    final parameters = {
      ...endpoint.queryParameters,
      'name': '$domain.',
      'type': 'TXT',
      'do': 'true',
      'cd': 'false',
      'edns_client_subnet': '0.0.0.0/0',
      'random_padding': 'X',
    };
    // The JSON API ignores this value; it hides the name length in 128-octet blocks.
    final length =
        endpoint.replace(queryParameters: parameters).toString().length;
    parameters['random_padding'] = 'X' * (1 + (128 - length % 128) % 128);
    final operation = transport.start(
        endpoint.replace(queryParameters: parameters),
        maxResponseBytes: maxResponseBytes);
    final result = Completer<AuthenticatedTxtResult>();
    late Timer timer;
    void release() {
      timer.cancel();
      try {
        operation.cancel();
      } catch (_) {}
    }

    void abort(DnsError code) {
      if (result.isCompleted) return;
      result.completeError(DnsException(code, 'DNS query ${code.name}'));
      release();
    }

    timer = Timer(timeout, () => abort(DnsError.timedOut));
    operation.result.then((response) {
      if (result.isCompleted) return;
      try {
        if (response.statusCode != 200) {
          throw DnsException(DnsError.transport, 'DNS HTTPS request failed',
              responseCode: response.statusCode);
        }
        if (response.body.length > maxResponseBytes) {
          throw const DnsException(
              DnsError.responseTooLarge, 'DNS body exceeds limit');
        }
        final body = jsonDecode(utf8.decode(response.body));
        result.complete(DnsResponse.fromJson(body, resolver: endpoint)
            .authenticatedTxt(domain));
      } on DnsException catch (error, stack) {
        result.completeError(error, stack);
      } on FormatException catch (_, stack) {
        result.completeError(
            const DnsException(
                DnsError.malformedResponse, 'Invalid DNS JSON encoding'),
            stack);
      } finally {
        release();
      }
    }, onError: (Object error, StackTrace stack) {
      release();
      if (!result.isCompleted) {
        result.completeError(
            error is DnsException
                ? error
                : const DnsException(
                    DnsError.transport, 'DNS transport failed'),
            stack);
      }
    });
    return DnsOperation(result.future, () => abort(DnsError.cancelled));
  }
}
