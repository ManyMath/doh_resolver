import 'dart:async';
import 'dart:convert';
import 'dns.dart';

/// A started request. Starting never throws: every failure, including
/// invalid input, completes [result] with a [DnsException].
class DnsOperation<T> {
  final Future<T> result;
  final void Function() cancel;
  const DnsOperation(this.result, this.cancel);
  DnsOperation.failed(DnsException error) : this(Future.error(error), _noop);
}

void _noop() {}

class DohHttpResponse {
  final int statusCode;
  final List<int> body;
  // Time the response spent in HTTP caches; DNS TTLs must be reduced by it.
  final Duration age;
  DohHttpResponse(this.statusCode, List<int> body, {this.age = Duration.zero})
      : body = List.unmodifiable(body) {
    if (age < Duration.zero) throw ArgumentError.value(age, 'age');
  }
}

abstract interface class DohTransport {
  DnsOperation<DohHttpResponse> start(Uri uri, {required int maxResponseBytes});
}

abstract interface class DohWireTransport {
  /// Sends wire [query]. With [preserveMessage], the query is sent and the
  /// response returned exactly as exchanged, with no padding or ID rewrite,
  /// for transaction signatures such as SIG(0) that cover both messages.
  DnsOperation<DohHttpResponse> startWire(Uri uri, List<int> query,
      {required int maxResponseBytes, bool preserveMessage = false});
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
    try {
      domain = normalizeDnsName(domain);
    } on DnsException catch (error) {
      return DnsOperation.failed(error);
    }
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
    final DnsOperation<DohHttpResponse> operation;
    try {
      operation = transport.start(endpoint.replace(queryParameters: parameters),
          maxResponseBytes: maxResponseBytes);
    } on DnsException catch (error) {
      return DnsOperation.failed(error);
    } catch (_) {
      return DnsOperation.failed(
          const DnsTransportException('DNS transport failed'));
    }
    final result = Completer<AuthenticatedTxtResult>();
    late Timer timer;
    // Only an unfinished transport operation is cancelled; once its result
    // has completed, the transport owns no further work for this lookup.
    void abort(DnsException error) {
      if (result.isCompleted) return;
      result.completeError(error);
      timer.cancel();
      try {
        operation.cancel();
      } catch (_) {}
    }

    timer = Timer(
        timeout, () => abort(const DnsTimeoutException('DNS query timed out')));
    operation.result.then((response) {
      if (result.isCompleted) return;
      try {
        if (response.statusCode != 200) {
          throw DnsTransportException('DNS HTTPS request failed',
              httpStatus: response.statusCode);
        }
        if (response.body.length > maxResponseBytes) {
          throw const DnsResponseTooLargeException('DNS body exceeds limit');
        }
        final body = jsonDecode(utf8.decode(response.body));
        result.complete(
            DnsResponse.fromJson(body, resolver: endpoint, age: response.age)
                .authenticatedTxt(domain));
      } on DnsException catch (error, stack) {
        result.completeError(error, stack);
      } on FormatException catch (_, stack) {
        result.completeError(
            const DnsMalformedResponseException('Invalid DNS JSON encoding'),
            stack);
      } catch (_, stack) {
        // The deadline is cancelled below, so every outcome must complete here.
        result.completeError(
            const DnsMalformedResponseException('Unreadable DNS response'),
            stack);
      } finally {
        timer.cancel();
      }
    }, onError: (Object error, StackTrace stack) {
      timer.cancel();
      if (!result.isCompleted) {
        result.completeError(
            error is DnsException
                ? error
                : const DnsTransportException('DNS transport failed'),
            stack);
      }
    });
    return DnsOperation(result.future,
        () => abort(const DnsCancelledException('DNS query cancelled')));
  }
}
