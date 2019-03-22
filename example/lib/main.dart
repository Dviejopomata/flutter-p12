import 'dart:io';
import 'dart:typed_data';
import 'package:file_picker/file_picker.dart';

import 'package:flutter/material.dart';

import 'package:flutter/services.dart';
import 'package:flutter_pfx/flutter_pfx.dart';

void main() => runApp(MyApp());

class MyApp extends StatefulWidget {
  @override
  _MyAppState createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String _path = "";

  List<int> _data;

  TextEditingController _passwordController = new TextEditingController();
  TextEditingController _dataToSignController = new TextEditingController();

  SignWithP12Result _signature;
  SignResult _signature2;

  @override
  void initState() {
    super.initState();
    _dataToSignController.text = "Hello world";
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
          appBar: AppBar(
            title: const Text('Plugin example app'),
          ),
          body: ListView(
            children: <Widget>[
              Text(
                'General',
                style: Theme.of(context).textTheme.subhead,
              ),
              RaisedButton(
                onPressed: () async {
                  var certificate = await FlutterPfx().chooseCertificate();
                  print(certificate);
                },
                child: Text("Elegir certificado"),
              ),
              SizedBox(
                height: 50,
              ),
              Text(
                'Sign with P12',
                style: Theme.of(context).textTheme.headline,
              ),
              RaisedButton(
                onPressed: () async {
                  try {
                    var path = await FilePicker.getFilePath(type: FileType.ANY);
                    setState(() {
                      _path = path != null ? path.split("/").last : "";
                    });
                    var file = File(path);
                    _data = await file.readAsBytes();
                  } on PlatformException catch (e) {
                    print("Unsupported operation" + e.toString());
                  }
                },
                child: Text("Upload P12 \n $_path"),
              ),
              TextFormField(
                controller: _passwordController,
                decoration: InputDecoration(
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(3.0),
                  ),
                  labelText: "Password",
                ),
              ),
              TextFormField(
                controller: _dataToSignController,
                decoration: InputDecoration(
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(3.0),
                  ),
                  labelText: "Text to sign",
                ),
              ),
              RaisedButton(
                child: Text("Sign data"),
                onPressed: () async {
                  var signature = await FlutterPfx().signWithP12(
                    data: Uint8List.fromList(
                        _dataToSignController.text.codeUnits),
                    p12: _data,
                    password: _passwordController.text,
                  );
                  setState(() {
                    _signature = signature;
                  });
                },
              ),
              Text(
                  "Signature is ${_signature != null ? _signature.signature : ""}"),
              RaisedButton(
                child: Text("Sign data with any certificate"),
                onPressed: () async {
                  final signature = await FlutterPfx().sign(
                    Uint8List.fromList(_dataToSignController.text.codeUnits),
                  );
                  print(signature.signature);
                  print(signature.certificate);
                  setState(() {
                    _signature2 = signature;
                  });
                },
              ),
              Text(
                  "Signature is ${_signature2 != null ? _signature2.signature : ""}"),
              Text(
                  "Certificate is ${_signature2 != null ? _signature2.certificate : ""}"),
            ],
          )),
    );
  }
}
