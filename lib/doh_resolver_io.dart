/// Everything in `doh_resolver`, plus [IoDohTransport] for direct and SOCKS5
/// HTTPS on `dart:io` platforms.
library;

export 'package:socks_socket/socks_connection.dart' show SocksCredentials;

export 'doh_resolver.dart';
export 'src/io_transport.dart';
