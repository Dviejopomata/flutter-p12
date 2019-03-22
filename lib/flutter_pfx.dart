import 'dart:async';
import 'dart:convert' show base64Encode;
import 'dart:typed_data';

import 'package:flutter/services.dart';

class CustomException implements Exception {
  CustomException(this.cause);

  String cause;
}

class NoCertificateException implements Exception {
  NoCertificateException(this.cause);

  String cause;
}

class BadPasswordP12Exception implements Exception {
  BadPasswordP12Exception(this.cause);

  String cause;
}

class BadFormatP12Exception implements Exception {
  BadFormatP12Exception(this.cause);

  String cause;
}

class UnknownP12Exception implements Exception {
  UnknownP12Exception(this.cause);

  String cause;
}

class CertificateResult {
  CertificateResult({this.b64});

  String b64;
}

class SignWithP12Result {
  SignWithP12Result({this.signature});

  String signature;
}

class SignResult {
  SignResult({this.signature, this.certificate});

  String signature;
  String certificate;
}

class FlutterPfx {
  FlutterPfx();

  MethodChannel channel = const MethodChannel('flutter_pfx');

  Future<String> get platformVersion async {
    final String version = await channel.invokeMethod('getPlatformVersion');
    return version;
  }

  Future<SignResult> sign(Uint8List data) async {
    try {
      final String signatureB64 = await channel.invokeMethod('signData', {
        'data': data,
      });
      var chunks = signatureB64.split(";");
      return SignResult(signature: chunks[0], certificate: chunks[1]);
    } catch (e) {
      if (e is PlatformException) {
        switch (e.code) {
          case "BAD_PASSWORD":
            throw BadPasswordP12Exception(e.message);
          case "BAD_CERTIFICATE_FORMAT":
            throw BadFormatP12Exception(e.message);
          case "CERTIFICATE_ERROR":
            throw UnknownP12Exception(e.message);
          default:
            rethrow;
        }
      } else {
        rethrow;
      }
    }
  }

  Future<CertificateResult> chooseCertificate() async {
    try {
      final Uint8List crtB64 = await channel.invokeMethod('getCertificate');
      return CertificateResult(b64: base64Encode(crtB64));
    } catch (e) {
      if (e is PlatformException) {
        switch (e.code) {
          case "NO_CERTIFICATE_CHOSEN":
            throw NoCertificateException(e.message);
          default:
            rethrow;
        }
      } else {
        rethrow;
      }
    }
  }

  Future<SignWithP12Result> signWithP12(
      {Uint8List p12, String password, Uint8List data}) async {
    try {
      final Uint8List signatureB64 =
          await channel.invokeMethod('signDataWithPfx', {
        'pfx': p12,
        'password': password,
        'data': data,
      });

      return SignWithP12Result(signature: base64Encode(signatureB64));
    } catch (e) {
      if (e is PlatformException) {
        switch (e.code) {
          case "BAD_PASSWORD":
            throw BadPasswordP12Exception(e.message);
          case "BAD_CERTIFICATE_FORMAT":
            throw BadFormatP12Exception(e.message);
          case "CERTIFICATE_ERROR":
            throw UnknownP12Exception(e.message);
          default:
            rethrow;
        }
      } else {
        rethrow;
      }
    }
  }

  Future<CertificateResult> readP12({Uint8List p12, String password}) async {
    try {
      final Uint8List crtB64 = await channel
          .invokeMethod('readPfx', {'pfx': p12, 'password': password});
      return CertificateResult(b64: base64Encode(crtB64));
    } catch (e) {
      if (e is PlatformException) {
        switch (e.code) {
          case "BAD_PASSWORD":
            throw BadPasswordP12Exception(e.message);
          case "BAD_CERTIFICATE_FORMAT":
            throw BadFormatP12Exception(e.message);
          case "CERTIFICATE_ERROR":
            throw UnknownP12Exception(e.message);
          default:
            rethrow;
        }
      } else {
        rethrow;
      }
    }
  }
}
