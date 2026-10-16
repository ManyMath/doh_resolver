import 'dart:async';
import 'dart:collection';

import 'package:doh_resolver/doh_resolver.dart';

/// Replays scripted responses and records requests and cancellations.
///
/// Each script entry answers one request: a [DohResolverResponse] completes
/// it, anything else fails it. Without an entry a request stays pending until
/// [respond] or [fail].
class FakeDohResolverTransport implements DohResolverTransport {
  FakeDohResolverTransport([Iterable<Object> script = const []])
      : _script = Queue.of(script);

  final Queue<Object> _script;
  final requests = <Uri>[];
  final _pending = <Completer<DohResolverResponse>>[];
  int cancellations = 0;
  bool throwOnCancel = false;

  /// Thrown from [start] instead of returning an operation.
  Object? throwOnStart;

  Uri? get uri => requests.isEmpty ? null : requests.last;
  bool get cancelled => cancellations > 0;

  void respond(DohResolverResponse response) {
    if (!_pending.last.isCompleted) _pending.last.complete(response);
  }

  void fail(Object error) {
    if (!_pending.last.isCompleted) _pending.last.completeError(error);
  }

  @override
  DohResolverOperation<DohResolverResponse> start(Uri uri,
      {required int maxResponseBytes}) {
    final error = throwOnStart;
    if (error != null) throw error;
    requests.add(uri);
    final completer = Completer<DohResolverResponse>();
    _pending.add(completer);
    if (_script.isNotEmpty) {
      final next = _script.removeFirst();
      if (next is DohResolverResponse) {
        completer.complete(next);
      } else {
        completer.completeError(next);
      }
    }
    return DohResolverOperation(completer.future, () {
      cancellations++;
      if (!completer.isCompleted) {
        completer.completeError(const DohResolverCancelledException('cancelled',
            source: DohResolverCancellationSource.transport));
      }
      if (throwOnCancel) throw StateError('cancel failed');
    });
  }
}
