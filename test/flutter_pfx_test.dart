// import 'package:test/test.dart';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_pfx/flutter_pfx.dart';
import 'package:flutter_test/flutter_test.dart';

Future<dynamic> fakePlatformViewsMethodHandler(MethodCall call) {
  switch (call.method) {
    case 'getPlatformVersion':
      return Future<String>.value("3.0");
    case 'chooseCertificate':
      return Future<String>.value();
    default:
      return Future<void>.sync(() {});
  }
}

void main() {
  FlutterPfx flutterPfx;
  setUp(() {
    flutterPfx = FlutterPfx();
  });
  test('get platform version test', () async {
    flutterPfx.channel.setMockMethodCallHandler(fakePlatformViewsMethodHandler);
    var platformVersion = await flutterPfx.platformVersion;
    expect(platformVersion, "3.0");
  });
  test('get certificate', () async {
    var expectedValue = "hi, how are you";
    flutterPfx.channel.setMockMethodCallHandler((channel) {
      switch (channel.method) {
        case 'getCertificate':
          return Future<String>.value(expectedValue);
        default:
          throw Exception("Not implemented");
      }
    });
    var crt = await flutterPfx.chooseCertificate();
    expect(crt.b64, expectedValue);
  });

  test('read p12', () async {
    var expectedValue = "hi, how are you";
    flutterPfx.channel.setMockMethodCallHandler((channel) {
      switch (channel.method) {
        case 'readPfx':
          return Future<String>.value(expectedValue);
        default:
          throw Exception("Not implemented");
      }
    });
    var crt = await flutterPfx.readP12();
    expect(crt.b64, expectedValue);
  });
}
