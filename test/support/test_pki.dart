import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

class TestPki {
  final String caPem;
  final String leafPem;
  final String keyPem;
  TestPki._(this.caPem, this.leafPem, this.keyPem);

  factory TestPki.generate(
      {List<String> dnsNames = const ['localhost'],
      List<InternetAddress>? ipAddresses,
      Duration validity = const Duration(days: 30)}) {
    final now = DateTime.now().toUtc();
    final notBefore = now.subtract(const Duration(hours: 1));
    final notAfter = now.add(validity);
    final ca = _generateKey();
    final leaf = _generateKey();
    final caName = _name('doh_resolver test CA');
    final caCert = _certificate(
        issuer: caName,
        subject: caName,
        subjectKey: ca,
        signingKey: ca,
        notBefore: notBefore,
        notAfter: notAfter,
        extensions: [
          _extension(
              '2.5.29.19',
              _seq([
                _der(0x01, [0xff])
              ]),
              critical: true),
          _extension('2.5.29.15', [0x03, 0x02, 0x01, 0x06], critical: true),
          _extension('2.5.29.14', _der(0x04, _keyId(ca))),
        ]);
    final ips = ipAddresses ?? [InternetAddress.loopbackIPv4];
    final leafCert = _certificate(
        issuer: caName,
        subject: _name(dnsNames.first),
        subjectKey: leaf,
        signingKey: ca,
        notBefore: notBefore,
        notAfter: notAfter,
        extensions: [
          _extension('2.5.29.19', _seq([]), critical: true),
          _extension('2.5.29.15', [0x03, 0x02, 0x07, 0x80], critical: true),
          _extension('2.5.29.37', _seq([_oid('1.3.6.1.5.5.7.3.1')])),
          _extension(
              '2.5.29.17',
              _seq([
                for (final name in dnsNames) _der(0x82, ascii.encode(name)),
                for (final ip in ips) _der(0x87, ip.rawAddress),
              ])),
          _extension('2.5.29.35', _seq([_der(0x80, _keyId(ca))])),
        ]);
    return TestPki._(_pem('CERTIFICATE', caCert), _pem('CERTIFICATE', leafCert),
        _pem('PRIVATE KEY', _pkcs8(leaf)));
  }

  SecurityContext serverContext() => SecurityContext(withTrustedRoots: false)
    ..useCertificateChainBytes(utf8.encode(leafPem + caPem))
    ..usePrivateKeyBytes(utf8.encode(keyPem));

  SecurityContext clientContext() => SecurityContext(withTrustedRoots: false)
    ..setTrustedCertificatesBytes(utf8.encode(caPem));
}

final _domain = ECDomainParameters('prime256v1');

AsymmetricKeyPair<ECPublicKey, ECPrivateKey> _generateKey() {
  final seed = Random.secure();
  final random = FortunaRandom()
    ..seed(KeyParameter(
        Uint8List.fromList(List.generate(32, (_) => seed.nextInt(256)))));
  final generator = ECKeyGenerator()
    ..init(ParametersWithRandom(ECKeyGeneratorParameters(_domain), random));
  return generator.generateKeyPair();
}

List<int> _publicPoint(AsymmetricKeyPair<ECPublicKey, ECPrivateKey> key) =>
    key.publicKey.Q!.getEncoded(false);

List<int> _keyId(AsymmetricKeyPair<ECPublicKey, ECPrivateKey> key) =>
    SHA1Digest().process(Uint8List.fromList(_publicPoint(key)));

List<int> _certificate({
  required List<int> issuer,
  required List<int> subject,
  required AsymmetricKeyPair<ECPublicKey, ECPrivateKey> subjectKey,
  required AsymmetricKeyPair<ECPublicKey, ECPrivateKey> signingKey,
  required DateTime notBefore,
  required DateTime notAfter,
  required List<List<int>> extensions,
}) {
  final serial = Random.secure();
  final algorithm = _seq([_oid('1.2.840.10045.4.3.2')]);
  final tbs = _seq([
    _der(0xa0, _integer(BigInt.two)),
    _integer(BigInt.parse(
        List.generate(16, (_) => serial.nextInt(256).toRadixString(16))
            .map((b) => b.padLeft(2, '0'))
            .join(),
        radix: 16)),
    algorithm,
    issuer,
    _seq([_time(notBefore), _time(notAfter)]),
    subject,
    _spki(subjectKey),
    _der(0xa3, _seq(extensions)),
  ]);
  final signer = ECDSASigner(SHA256Digest(), HMac(SHA256Digest(), 64))
    ..init(true, PrivateKeyParameter<ECPrivateKey>(signingKey.privateKey));
  final signature =
      signer.generateSignature(Uint8List.fromList(tbs)) as ECSignature;
  return _seq([
    tbs,
    algorithm,
    _der(0x03, [
      0,
      ..._seq([_integer(signature.r), _integer(signature.s)])
    ]),
  ]);
}

List<int> _spki(AsymmetricKeyPair<ECPublicKey, ECPrivateKey> key) => _seq([
      _seq([_oid('1.2.840.10045.2.1'), _oid('1.2.840.10045.3.1.7')]),
      _der(0x03, [0, ..._publicPoint(key)]),
    ]);

List<int> _pkcs8(AsymmetricKeyPair<ECPublicKey, ECPrivateKey> key) {
  final d = key.privateKey.d!.toRadixString(16).padLeft(64, '0');
  final scalar = [
    for (var i = 0; i < 64; i += 2) int.parse(d.substring(i, i + 2), radix: 16)
  ];
  return _seq([
    _integer(BigInt.zero),
    _seq([_oid('1.2.840.10045.2.1'), _oid('1.2.840.10045.3.1.7')]),
    _der(
        0x04,
        _seq([
          _integer(BigInt.one),
          _der(0x04, scalar),
          _der(0xa1, _der(0x03, [0, ..._publicPoint(key)])),
        ])),
  ]);
}

List<int> _name(String commonName) => _seq([
      _der(0x31, _seq([_oid('2.5.4.3'), _der(0x0c, utf8.encode(commonName))]))
    ]);

List<int> _extension(String oid, List<int> value, {bool critical = false}) =>
    _seq([
      _oid(oid),
      if (critical) _der(0x01, [0xff]),
      _der(0x04, value),
    ]);

List<int> _time(DateTime time) {
  String two(int value) => value.toString().padLeft(2, '0');
  return _der(
      0x17,
      ascii.encode('${two(time.year % 100)}${two(time.month)}${two(time.day)}'
          '${two(time.hour)}${two(time.minute)}${two(time.second)}Z'));
}

List<int> _integer(BigInt value) {
  var hex = value.toRadixString(16);
  if (hex.length.isOdd) hex = '0$hex';
  final bytes = [
    for (var i = 0; i < hex.length; i += 2)
      int.parse(hex.substring(i, i + 2), radix: 16)
  ];
  return _der(0x02, bytes.first >= 0x80 ? [0, ...bytes] : bytes);
}

List<int> _oid(String dotted) {
  final parts = dotted.split('.').map(int.parse).toList();
  final body = <int>[parts[0] * 40 + parts[1]];
  for (final part in parts.skip(2)) {
    final chunk = <int>[part & 0x7f];
    for (var v = part >> 7; v > 0; v >>= 7) {
      chunk.insert(0, 0x80 | (v & 0x7f));
    }
    body.addAll(chunk);
  }
  return _der(0x06, body);
}

List<int> _seq(List<List<int>> items) =>
    _der(0x30, [for (final item in items) ...item]);

List<int> _der(int tag, List<int> body) {
  final length = body.length;
  if (length < 0x80) return [tag, length, ...body];
  final bytes = <int>[];
  for (var v = length; v > 0; v >>= 8) {
    bytes.insert(0, v & 0xff);
  }
  return [tag, 0x80 | bytes.length, ...bytes, ...body];
}

String _pem(String label, List<int> der) {
  final encoded = base64.encode(der);
  final lines = [
    for (var i = 0; i < encoded.length; i += 64)
      encoded.substring(i, min(i + 64, encoded.length))
  ];
  return '-----BEGIN $label-----\n${lines.join('\n')}\n-----END $label-----\n';
}
