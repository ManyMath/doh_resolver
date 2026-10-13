import 'dart:async';
import 'dart:convert';
import 'dart:io';

class ScriptedExchange {
  final SecureSocket socket;
  final int connection;
  final int index;
  final List<int> body;
  ScriptedExchange(this.socket, this.connection, this.index, this.body);

  int get id => body[0] << 8 | body[1];

  void send(List<int> bytes) {
    try {
      socket.add(bytes);
    } catch (_) {}
  }
}

List<int> httpResponse(List<int> body,
    {int status = 200,
    String type = 'application/dns-message',
    bool chunked = false}) {
  final head = 'HTTP/1.1 $status X\r\ncontent-type: $type\r\n'
      '${chunked ? 'transfer-encoding: chunked' : 'content-length: ${body.length}'}'
      '\r\n\r\n';
  return [
    ...latin1.encode(head),
    if (chunked && body.isNotEmpty) ...[
      ...latin1.encode('${body.length.toRadixString(16)}\r\n'),
      ...body,
      ...latin1.encode('\r\n'),
    ],
    if (chunked) ...latin1.encode('0\r\n\r\n') else ...body,
  ];
}

class ScriptedServer {
  final SecurityContext context;
  final FutureOr<void> Function(ScriptedExchange exchange) handler;
  late SecureServerSocket _server;
  final _sockets = <SecureSocket>[];
  final exchanges = <ScriptedExchange>[];
  int connections = 0;
  int closed = 0;
  ScriptedServer(this.context, this.handler);

  int get port => _server.port;

  Future<void> start() async {
    _server =
        await SecureServerSocket.bind(InternetAddress.loopbackIPv4, 0, context);
    _server.listen(_serve, onError: (Object _) {});
  }

  void _serve(SecureSocket socket) {
    final connection = ++connections;
    _sockets.add(socket);
    socket.done.ignore();
    var buffer = <int>[];
    socket.listen((data) {
      buffer.addAll(data);
      while (true) {
        final end =
            latin1.decode(buffer, allowInvalid: true).indexOf('\r\n\r\n');
        if (end < 0) return;
        final head = latin1.decode(buffer.sublist(0, end)).toLowerCase();
        final size = int.parse(
            RegExp(r'content-length: *(\d+)').firstMatch(head)?.group(1) ??
                '0');
        if (buffer.length < end + 4 + size) return;
        final exchange = ScriptedExchange(socket, connection,
            exchanges.length + 1, buffer.sublist(end + 4, end + 4 + size));
        buffer = buffer.sublist(end + 4 + size);
        exchanges.add(exchange);
        runZonedGuarded(() => handler(exchange), (_, __) {});
      }
    }, onError: (Object _) {}, onDone: () => closed++);
  }

  Future<void> close() async {
    for (final socket in _sockets) {
      socket.destroy();
    }
    await _server.close();
  }
}
