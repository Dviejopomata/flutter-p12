package com.dviejopomata.flutterpfx

import android.app.Activity
import android.security.KeyChain
import android.util.Base64
import android.util.Log
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.PluginRegistry.Registrar
import io.reactivex.Observable
import java.io.ByteArrayInputStream
import java.io.EOFException
import java.io.IOException
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate

class FlutterPfxPlugin : MethodCallHandler {
    companion object {
        @JvmStatic
        fun registerWith(registrar: Registrar) {
            val channel = MethodChannel(registrar.messenger(), "flutter_pfx")
            channel.setMethodCallHandler(FlutterPfxPlugin(registrar.activity()))
        }
    }

    private var activity: Activity

    constructor(activity: Activity) {
        this.activity = activity;
    }

    override fun onMethodCall(call: MethodCall, result: Result) {

        when (call.method) {
            "getCertificate" -> GetCertificate(activity, result)
            "signData" -> SignData(activity, result, call.argument<ByteArray>("data")!!)
            "signDataWithPfx" -> SignDataWithPfx(result, call.argument<ByteArray>("pfx")!!, call.argument<String>("password")!!, call.argument<ByteArray>("data")!!)
            "readPfx" -> {
                try {
                    val certificate = getCertificate(call.argument<ByteArray>("pfx")!!, call.argument<String>("password")!!)
                    result.success(certificate)
                } catch (ex: IOException) {
                    result.error("BAD_PASSWORD", ex.message, null)
                } catch (ex: EOFException) {
                    result.error("BAD_CERTIFICATE_FORMAT", ex.message, null)
                } catch (ex: java.lang.Exception) {
                    result.error("CERTIFICATE_ERROR", ex.message, null)
                }
            }
            else -> result.notImplemented()
        }
    }

    private fun SignDataWithPfx(result: MethodChannel.Result, pfx: ByteArray, password: String, data: ByteArray) {
        try {
            val pk = getPrivateKey(pfx, password)
            result.success(SignWithPrivateKey(pk.privateKey, data))
        } catch (ex: IOException) {
            result.error("BAD_PASSWORD", ex.message, null)
        } catch (ex: EOFException) {
            result.error("BAD_CERTIFICATE_FORMAT", ex.message, null)
        } catch (ex: java.lang.Exception) {
            result.error("CERTIFICATE_ERROR", ex.message, null)
        }
    }

    private fun SignWithPrivateKey(pk: PrivateKey, data: ByteArray): ByteArray {
        val sig = Signature.getInstance("SHA1WithRSA")
        sig.initSign(pk)
        sig.update(data)
        return sig.sign()
    }

    private fun SignData(activity: Activity, result: MethodChannel.Result, data: ByteArray) {
        chooseCertificate(activity)
                .subscribe({
                    val signature = Base64.encodeToString(SignWithPrivateKey(it.first, data), Base64.DEFAULT)
                    val crt = Base64.encodeToString(it.second.first().encoded, Base64.DEFAULT)
                    result.success("$signature;$crt")
                }, {
                    if (it is NoCertificateException) {
                        result.error("NO_CERTIFICATE_CHOSEN", it.message, null)
                    } else {
                        result.error("UNKNOWN_ERROR", it.message, null)
                    }
                })

    }


    private fun GetCertificate(activity: Activity, result: MethodChannel.Result) {
        chooseCertificate(activity)
                .subscribe(
                        { r ->

                            val map = r.second.first()
                            result.success(map.encoded)
                        },
                        {
                            if (it is NoCertificateException) {
                                result.error("NO_CERTIFICATE_CHOSEN", it.message, null)
                            } else {
                                result.error("UNKNOWN_ERROR", it.message, null)
                            }
                        }
                )
    }

    class NoCertificateException(message: String) : Exception(message)

    private fun chooseCertificate(activity: Activity): Observable<Pair<PrivateKey, Array<X509Certificate>>> {
        return Observable.create {
            KeyChain.choosePrivateKeyAlias(activity, { alias ->
                if (alias == null) {
                    it.onError(NoCertificateException("No se ha seleccionado ningun certificado"))
                    return@choosePrivateKeyAlias
                }
                Log.d("CERT", "Alias is $alias")
                val privateKey = KeyChain.getPrivateKey(
                        activity,
                        alias
                )
                val certs = KeyChain.getCertificateChain(activity, alias)
                it.onNext(Pair(privateKey, certs))
                it.onComplete()
            }, arrayOf("RSA"), null, null, -1, null)
        }
    }

    fun getCertificate(data: ByteArray, password: String): ByteArray {
        val p12 = getP12(data, password)!!
        val e = p12.aliases()
        val alias = e.nextElement() as String
        val c = p12.getCertificate(alias) as X509Certificate
        return c.encoded!!
    }

    fun getPrivateKey(data: ByteArray, password: String): KeyStore.PrivateKeyEntry {
        val p12 = getP12(data, password)!!
        val e = p12.aliases()
        val alias = e.nextElement() as String
        val entry = p12.getEntry(alias, KeyStore.PasswordProtection("".toCharArray()))
        return entry as KeyStore.PrivateKeyEntry

    }

    private fun getP12(data: ByteArray, password: String): KeyStore? {
        val p12 = KeyStore.getInstance("pkcs12")
        p12.load(ByteArrayInputStream(data), password.toCharArray())
        return p12
    }
}
