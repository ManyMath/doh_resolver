import 'dart:async';
import 'dart:convert';

import 'dns.dart';
import 'names.dart';
import 'transport.dart';

/// Looks up TXT records through a DoH JSON API and accepts only answers the
/// resolver asserts are DNSSEC-authenticated.
///
/// This trusts the resolver's AD flag.
class DohResolver {
  final DohResolverTransport transport;
  final Uri endpoint;

  /// The deadline for a whole lookup. The transport may enforce its own,
  /// too; whichever is earlier applies.
  final Duration timeout;
  final int maxResponseBytes;

  /// How [endpoint] writes TXT data. Known Google and Cloudflare hosts get
  /// their format by default; any other endpoint must pass it explicitly.
  final DnsTxtFormat txtFormat;
  late final Map<String, List<String>> _endpointParameters;

  /// Creates a resolver for [endpoint], Google's JSON API by default.
  ///
  /// Throws [ArgumentError] for an unusable [endpoint], invalid limits, or an
  /// unknown provider without [txtFormat]. Endpoint query parameters are kept
  /// except those the resolver sets itself.
  DohResolver(
      {required this.transport,
      Uri? endpoint,
      this.timeout = const Duration(seconds: 12),
      this.maxResponseBytes = 65536,
      DnsTxtFormat? txtFormat})
      : endpoint = endpoint ??= Uri.https('dns.google', '/resolve'),
        txtFormat = txtFormat ??
            _knownTxtFormat(endpoint.host) ??
            (throw ArgumentError.value(endpoint, 'endpoint',
                'Pass txtFormat: JSON TXT encoding differs between providers')) {
    if (!isUsableEndpoint(this.endpoint)) {
      throw ArgumentError(
          'A credential-free HTTPS resolver endpoint is required');
    }
    if (timeout <= Duration.zero || maxResponseBytes < 1) {
      throw ArgumentError('Invalid query limits');
    }
    try {
      _endpointParameters = this.endpoint.queryParametersAll;
    } on FormatException catch (error) {
      throw ArgumentError.value(
          this.endpoint, 'endpoint', 'Undecodable query: ${error.message}');
    }
  }

  /// Looks up [domain]'s TXT records; see [startTxtLookup].
  Future<ResolverAssertedTxtResult> lookupTxt(String domain) =>
      startTxtLookup(domain).result;

  /// Starts a cancellable TXT lookup for [domain].
  ///
  /// Sends `do=true`, `cd=false` and `edns_client_subnet=0.0.0.0/0`, and pads
  /// the URL to a multiple of 128 characters. Never throws: every failure is a
  /// [DohResolverException] in the result.
  DohResolverOperation<ResolverAssertedTxtResult> startTxtLookup(
      String domain) {
    try {
      domain = normalizeDnsName(domain);
    } on DohResolverInvalidNameException catch (error) {
      return DohResolverOperation.failed(error);
    }
    // Preserve repeated endpoint parameters; resolver-supplied parameters take precedence.
    final parameters = <String, Object>{
      ..._endpointParameters,
      'name': '$domain.',
      'type': 'TXT',
      'do': 'true',
      'cd': 'false',
      'edns_client_subnet': '0.0.0.0/0',
      'random_padding': 'X',
    };
    final length =
        endpoint.replace(queryParameters: parameters).toString().length;
    parameters['random_padding'] = 'X' * (1 + (128 - length % 128) % 128);
    final DohResolverOperation<DohResolverResponse> operation;
    try {
      operation = transport.start(endpoint.replace(queryParameters: parameters),
          maxResponseBytes: maxResponseBytes);
    } on DohResolverException catch (error) {
      return DohResolverOperation.failed(error);
    } catch (error, stack) {
      return DohResolverOperation.failed(DohResolverTransportException(
          'DNS transport failed',
          cause: error,
          causeStackTrace: stack));
    }
    final result = Completer<ResolverAssertedTxtResult>();
    late Timer timer;
    void abort(DohResolverException error) {
      if (result.isCompleted) return;
      result.completeError(error);
      timer.cancel();
      try {
        operation.cancel();
      } catch (_) {}
    }

    timer = Timer(
        timeout,
        () => abort(DohResolverLookupTimeoutException('DNS query timed out',
            timeout: timeout)));
    operation.result.then((response) {
      if (result.isCompleted) return;
      try {
        if (response.statusCode != 200) {
          throw DohResolverHttpStatusException('DNS HTTPS request failed',
              statusCode: response.statusCode);
        }
        if (response.body.length > maxResponseBytes) {
          throw DohResolverResponseTooLargeException('DNS body exceeds limit',
              kind: DohResolverLimitKind.responseBytes,
              maximum: maxResponseBytes,
              actual: response.body.length);
        }
        final body = jsonDecode(utf8.decode(response.body));
        result.complete(
            DnsResponse.fromJson(body, resolver: endpoint, age: response.age)
                .authenticatedTxt(domain, txtFormat: txtFormat));
      } on DohResolverException catch (error, stack) {
        result.completeError(error, stack);
      } on FormatException catch (_, stack) {
        result.completeError(
            const DohResolverMalformedResponseException(
                'Invalid DNS JSON encoding'),
            stack);
      } catch (error, stack) {
        result.completeError(
            DohResolverMalformedResponseException('Unreadable DNS response',
                cause: error, causeStackTrace: stack),
            stack);
      } finally {
        timer.cancel();
      }
    }, onError: (Object error, StackTrace stack) {
      timer.cancel();
      if (!result.isCompleted) {
        result.completeError(
            error is DohResolverException
                ? error
                : DohResolverTransportException('DNS transport failed',
                    cause: error, causeStackTrace: stack),
            stack);
      }
    });
    return DohResolverOperation(
        result.future,
        () => abort(const DohResolverCancelledException('DNS query cancelled',
            source: DohResolverCancellationSource.caller)));
  }
}

DnsTxtFormat? _knownTxtFormat(String host) => switch (host) {
      'dns.google' ||
      'dns.google.com' ||
      '8.8.8.8' ||
      '8.8.4.4' =>
        DnsTxtFormat.raw,
      'cloudflare-dns.com' ||
      'one.one.one.one' ||
      '1.1.1.1' ||
      '1.0.0.1' =>
        DnsTxtFormat.quoted,
      _ when host.endsWith('.cloudflare-dns.com') => DnsTxtFormat.quoted,
      _ => null,
    };
