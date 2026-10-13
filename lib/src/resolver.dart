import 'dart:async';
import 'dart:convert';
import 'dns.dart';

/// A started request. Starting never throws: every failure, including
/// invalid input, completes [result] with a [DnsException].
class DnsOperation<T> {
  /// Completes with the outcome. Like any [Future], an error nobody listens
  /// to is reported as uncaught; cancelling does not consume it, so attach a
  /// handler or call [FutureExtensions.ignore] on results you discard.
  final Future<T> result;

  /// Fails [result] with [DnsCancelledException] unless it has already
  /// completed, and releases the work. Safe to call repeatedly.
  final void Function() cancel;
  const DnsOperation(this.result, this.cancel);

  /// An operation that has already failed with [error].
  DnsOperation.failed(DnsException error) : this(Future.error(error), _noop);
}

void _noop() {}

/// A complete HTTPS response from a DoH resolver.
class DohHttpResponse {
  final int statusCode;
  final List<int> body;

  /// Time the response spent in HTTP caches, from its `Age` header. DNS TTLs
  /// must be reduced by it; see [effectiveDnsTtl] and [adjustDnsWireTtls].
  final Duration age;
  DohHttpResponse(this.statusCode, List<int> body, {this.age = Duration.zero})
      : body = List.unmodifiable(body) {
    if (age < Duration.zero) throw ArgumentError.value(age, 'age');
  }
}

/// Sends DoH JSON GET requests.
///
/// Implementations must deliver every failure through the returned
/// [DnsOperation.result], bound the body to `maxResponseBytes`, and make
/// `cancel` idempotent. [DohResolver] cancels only operations that have not
/// completed.
abstract interface class DohTransport {
  DnsOperation<DohHttpResponse> start(Uri uri, {required int maxResponseBytes});
}

/// Sends RFC 8484 wire-format queries; see [DohTransport] for the contract.
abstract interface class DohWireTransport {
  /// Sends wire [query]. With [preserveMessage], the query is sent and the
  /// response returned exactly as exchanged, with no padding or ID rewrite,
  /// for transaction signatures such as SIG(0) that cover both messages.
  DnsOperation<DohHttpResponse> startWire(Uri uri, List<int> query,
      {required int maxResponseBytes, bool preserveMessage = false});
}

/// Looks up TXT records through a DoH JSON API and accepts only answers the
/// resolver asserts are DNSSEC-authenticated.
///
/// This trusts the resolver's AD flag: use a local validator with
/// [DnsValidationIssuer] when the resolver must not choose the answer.
class DohResolver {
  final DohTransport transport;
  final Uri endpoint;

  /// The deadline for a whole lookup. The transport may enforce its own,
  /// too; whichever is earlier applies.
  final Duration timeout;
  final int maxResponseBytes;

  /// How [endpoint] writes TXT data. Known Google and Cloudflare hosts get
  /// their format by default; any other endpoint must pass it explicitly.
  final DnsTxtFormat txtFormat;
  // Decoded once so a malformed endpoint fails construction, not each lookup.
  late final Map<String, List<String>> _endpointParameters;

  /// Creates a resolver for [endpoint], Google's JSON API by default.
  ///
  /// Throws [ArgumentError] for a non-HTTPS, credential-bearing,
  /// fragment-bearing or undecodable endpoint, invalid limits, or an unknown
  /// provider without [txtFormat]. Endpoint query parameters are kept,
  /// including repeated ones, except those the resolver sets itself.
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
    try {
      _endpointParameters = this.endpoint.queryParametersAll;
    } on FormatException catch (error) {
      throw ArgumentError.value(
          this.endpoint, 'endpoint', 'Undecodable query: ${error.message}');
    }
  }

  /// Looks up [domain]'s TXT records; see [startTxtLookup].
  Future<AuthenticatedTxtResult> lookupTxt(String domain) =>
      startTxtLookup(domain).result;

  /// Starts a cancellable TXT lookup for [domain].
  ///
  /// The request asks for DNSSEC data with checking enabled, sends
  /// `edns_client_subnet=0.0.0.0/0` (honoured by providers that implement it,
  /// such as Google), and pads the URL to a multiple of 128 characters so the
  /// name length is hidden. Never throws: every failure is a [DnsException] in
  /// the result.
  DnsOperation<AuthenticatedTxtResult> startTxtLookup(String domain) {
    try {
      domain = normalizeDnsName(domain);
    } on DnsException catch (error) {
      return DnsOperation.failed(error);
    }
    // Repeated endpoint parameters survive; the resolver's own keys override.
    final parameters = <String, Object>{
      ..._endpointParameters,
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
                .authenticatedTxt(domain, txtFormat: txtFormat));
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
