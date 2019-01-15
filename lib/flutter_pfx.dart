import 'dart:async';
import 'dart:io';
import 'dart:typed_data';
import 'dart:convert';

import 'package:flutter/services.dart';

class CustomException implements Exception {
  String cause;
  CustomException(this.cause);
}

class NoCertificateException implements Exception {
  String cause;
  NoCertificateException(this.cause);
}

class BadPasswordP12Exception implements Exception {
  String cause;
  BadPasswordP12Exception(this.cause);
}

class BadFormatP12Exception implements Exception {
  String cause;
  BadFormatP12Exception(this.cause);
}

class UnknownP12Exception implements Exception {
  String cause;
  UnknownP12Exception(this.cause);
}

class CertificateResult {
  String b64;
  CertificateResult({this.b64});
}

class SignWithP12Result {
  String signature;
  SignWithP12Result({this.signature});
}

class FlutterPfx {
  FlutterPfx();
  MethodChannel channel = const MethodChannel('flutter_pfx');

  Future<String> get platformVersion async {
    final String version = await channel.invokeMethod('getPlatformVersion');
    return version;
  }

  Future<CertificateResult> chooseCertificate() async {
    try {
      Uint8List crtB64 = await channel.invokeMethod('getCertificate');
      return CertificateResult(b64: base64Encode(crtB64));
    } catch (e) {
      if (e is PlatformException) {
        switch (e.code) {
          case "NO_CERTIFICATE_CHOSEN":
            throw NoCertificateException(e.message);
          default:
            throw e;
        }
      } else {
        throw e;
      }
    }
  }

  Future<SignWithP12Result> signWithP12(
      {Uint8List p12, String password, Uint8List data}) async {
    try {
      Uint8List signatureB64 = await channel.invokeMethod('signDataWithPfx', {
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
          case "BAD_CERTIFICATE_FORMAT":
            throw UnknownP12Exception(e.message);
          default:
            throw e;
        }
      } else {
        throw e;
      }
    }
  }

  Future<CertificateResult> readP12({Uint8List p12, String password}) async {
    try {
      Uint8List crtB64 = await channel
          .invokeMethod('readPfx', {'pfx': p12, 'password': password});
      return CertificateResult(b64: base64Encode(crtB64));
    } catch (e) {
      if (e is PlatformException) {
        var ex = e;
        switch (ex.code) {
          case "BAD_PASSWORD":
            throw BadPasswordP12Exception(ex.message);
          case "BAD_CERTIFICATE_FORMAT":
            throw BadFormatP12Exception(ex.message);
          case "BAD_CERTIFICATE_FORMAT":
            throw UnknownP12Exception(ex.message);
          default:
            throw e;
        }
      } else {
        throw e;
      }
    }
  }
}
