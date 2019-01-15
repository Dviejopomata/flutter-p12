import Flutter
import UIKit
import Foundation
import Security

public class SwiftFlutterPfxPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "flutter_pfx", binaryMessenger: registrar.messenger())
    let instance = SwiftFlutterPfxPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    executeFunc(call, result)
  }

  private func executeFunc(call: FlutterMethodCall, result:FlutterResult) throws {
        let dic = call.arguments as! [String: Any]
        switch call.method {
        case "getCertificate":
            print("Calling getCertificate!")
            result(FlutterMethodNotImplemented)
        case "signData":
            print("Calling signData!")
            result(FlutterMethodNotImplemented)
        case "signDataWithPfx":
            let pfx = dic["pfx"] as! FlutterStandardTypedData
            let data = dic["data"] as! FlutterStandardTypedData
            try self.signDataWithPfx(pfx.data as NSData, dic["password"] as! NSString, data.data as NSData, result)
        case "readPfx":
            let pfx = dic["pfx"] as! FlutterStandardTypedData
            try self.readPfx(pfx.data as NSData, dic["password"] as! NSString, result)
        default:
            print("Method not found")
            result(FlutterMethodNotImplemented)
        }
    }

    private func signDataWithPfx(_ pfx: NSData, _ password: NSString, _ data: NSData, _ result: FlutterResult) throws {
        let privateKeyResponse = self.getPrivateKey(pfx, password)
        guard privateKeyResponse.error == errSecSuccess else {
            let secError = privateKeyResponse.error
            if secError == errSecAuthFailed {
                result(FlutterError(code: "BAD_PASSWORD", message: "La contraseña es incorrecta", details: nil))
            } else {
                result(FlutterError(code: "FATAL_ERROR", message: "No ha sido posible realizar la extraccion del certificado \(secError)", details: nil))
            }
            return
        }
        
        guard let privateKey = privateKeyResponse.privateKey else {
            result(FlutterError(code: "PRIVATE_KEY_ERROR", message: "No ha sido posible realizar la extraccion de la clave privada", details: nil))
            return
        }
        let resultSign : RSASigningResult = self.sign(data: data as Data, privateKey: privateKey)
        guard resultSign.error == nil else {
            result(FlutterError(code: "ERROR_SIGN", message: "No ha sido posible firmar los datos con la clave privada \(resultSign.error!.description)", details: nil))
            return
        }
        result(resultSign.signedData)
    }

    private func readPfx(_ pfx: NSData, _ password: NSString, _ result: FlutterResult) throws {
        let certificateResponse = self.getCertificate(pfx, password)
        guard certificateResponse.error == errSecSuccess else {
            let secError = certificateResponse.error
            if secError == errSecAuthFailed {
                result(FlutterError(code: "BAD_PASSWORD", message: "La contraseña es incorrecta", details: nil))
            } else {
                result(FlutterError(code: "FATAL_ERROR", message: "No ha sido posible realizar la extraccion del certificado \(secError)", details: nil))
            }
            return
        }
        guard let certificate = certificateResponse.certificate else {
            result(FlutterError(code: "CERTIFICATE_ERROR", message: "No ha sido posible realizar la extraccion del certificado", details: nil))
            return
        }
        let data = SecCertificateCopyData(certificate) as Data
        let string = (data as Data).base64EncodedString(options: Data.Base64EncodingOptions(rawValue: 0))
        result(string)
    }

    private typealias IdentityResult = (identity: SecIdentity?, error: OSStatus)
    private func getIdentity(_ data: NSData, _ password: NSString) -> IdentityResult{
        let importPasswordOption:NSDictionary = [ kSecImportExportPassphrase : password]
        var items : CFArray?
        let secError : OSStatus = SecPKCS12Import(data,importPasswordOption, &items)
        guard secError == errSecSuccess else {
            return IdentityResult( identity: nil, error: secError )
        }
        let identityDictionaries = items as! [[String: Any]]
        let identity = identityDictionaries[0][kSecImportItemIdentity as String]
            as! SecIdentity
        return IdentityResult(identity: identity, error: errSecSuccess )
    }
    
    private typealias PrivateKeyResult = (privateKey: SecKey?, error: OSStatus)
    private func getPrivateKey(_ data:NSData, _ password: NSString ) -> PrivateKeyResult {
        let identityResult = getIdentity(data, password)
        guard identityResult.error == errSecSuccess else {
            return PrivateKeyResult(privateKey: nil, error: identityResult.error)
        }
        
        guard let identity = identityResult.identity else {
            return PrivateKeyResult( privateKey: nil, error: errSecBadReq )
        }
        
        var optPrivateKey: SecKey?
        let secError = SecIdentityCopyPrivateKey(identity, &optPrivateKey)
        guard secError == errSecSuccess else {
            return PrivateKeyResult(privateKey: nil, error: secError )
        }
        guard let privateKey = optPrivateKey else {
            return PrivateKeyResult(privateKey: nil, error: errSecBadReq )
        }
        return PrivateKeyResult(privateKey: privateKey, error: errSecSuccess )
    }
    
    private typealias CertificateResult = (certificate: SecCertificate?, error: OSStatus)
    private func getCertificate(_ data: NSData, _ password: NSString) -> CertificateResult {
        let identityResult = getIdentity(data, password)
        guard identityResult.error == errSecSuccess else {
            return CertificateResult(certificate: nil, error: identityResult.error)
        }
        
        guard let identity = identityResult.identity else {
            return CertificateResult( certificate: nil, error: errSecBadReq )
        }
        
        var optCertificateRef : SecCertificate?
        let secError = SecIdentityCopyCertificate(identity, &optCertificateRef)
        guard secError == errSecSuccess else {
            return CertificateResult( certificate : nil, error: secError )
        }
        
        guard let certificate = optCertificateRef else {
            return CertificateResult( certificate : nil,  error: errSecBadReq )
        }
        
        return CertificateResult( certificate : certificate, error: errSecSuccess)
    }

    private typealias RSASigningResult = (signedData: Data?, error: NSError?)
    private func sign(data plainData: Data, privateKey: SecKey!) -> RSASigningResult {
        // Then sign it
        let dataToSign = [UInt8](plainData)
        var signatureLen = SecKeyGetBlockSize(privateKey)
        var signature = [UInt8](repeating: 0, count: SecKeyGetBlockSize(privateKey))
        
        let err: OSStatus = SecKeyRawSign(privateKey,
                                          SecPadding.PKCS1,
                                          dataToSign,
                                          plainData.count,
                                          &signature, &signatureLen)
        
        if err == errSecSuccess {
            return (signedData: Data(bytes: signature), error: nil)
        }
        
        return (signedData: nil, error: NSError(domain: NSOSStatusErrorDomain, code: Int(err), userInfo: nil))
        
    }
}
