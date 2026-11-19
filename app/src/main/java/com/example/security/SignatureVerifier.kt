package com.example.security

import android.content.pm.PackageInfo
import android.content.pm.Signature
import android.os.Build
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.Date
import java.util.Locale

data class SignatureAnalysis(
  val hasSignature: Boolean,
  val sha256Fingerprint: String,
  val sha1Fingerprint: String,
  val subject: String,
  val issuer: String,
  val keyAlgorithmInfo: String,
  val keyBitLength: Int,
  val sigAlgName: String,
  val validFromMillis: Long,
  val validUntilMillis: Long,
  val isDebugCert: Boolean,
  val isExpired: Boolean,
  val isSelfSigned: Boolean,
  val isWeakKey: Boolean,
  val hasMultipleSigners: Boolean,
)

object SignatureVerifier {

  // Known AOSP testkey SHA-256 fingerprint (publicly documented debug/test signing key)
  private val KNOWN_TEST_KEY_SHA256 =
    setOf(
      "A4:0D:A8:0A:59:D1:70:CA:A9:50:CF:15:C1:8C:45:4D:47:A3:9B:26:98:9D:8B:64:0E:CD:74:5B:A7:1B:F5:DC"
    )

  fun analyze(packageInfo: PackageInfo): SignatureAnalysis {
    val signatures: List<Signature> = extractSignatures(packageInfo)
    if (signatures.isEmpty()) {
      return SignatureAnalysis(
        hasSignature = false,
        sha256Fingerprint = "SEM ASSINATURA",
        sha1Fingerprint = "N/A",
        subject = "Nenhum certificado encontrado",
        issuer = "N/A",
        keyAlgorithmInfo = "Desconhecido",
        keyBitLength = 0,
        sigAlgName = "N/A",
        validFromMillis = 0L,
        validUntilMillis = 0L,
        isDebugCert = false,
        isExpired = true,
        isSelfSigned = false,
        isWeakKey = true,
        hasMultipleSigners = false,
      )
    }

    val primaryBytes = signatures.first().toByteArray()
    val sha256 = digestHex(primaryBytes, "SHA-256")
    val sha1 = digestHex(primaryBytes, "SHA-1")

    return try {
      val certFactory = CertificateFactory.getInstance("X.509")
      val cert = certFactory.generateCertificate(ByteArrayInputStream(primaryBytes)) as X509Certificate

      val subject = cert.subjectX500Principal.name
      val issuer = cert.issuerX500Principal.name
      val now = Date()
      val isExpired = now.after(cert.notAfter) || now.before(cert.notBefore)
      val isSelfSigned = cert.subjectX500Principal == cert.issuerX500Principal

      val pubKey = cert.publicKey
      val keyBits =
        when (pubKey) {
          is RSAPublicKey -> pubKey.modulus.bitLength()
          is ECPublicKey -> pubKey.params?.order?.bitLength() ?: 256
          else -> 0
        }
      val keyAlgDesc =
        if (keyBits > 0) "${pubKey.algorithm} ${keyBits}-bit (${cert.sigAlgName})"
        else "${pubKey.algorithm} (${cert.sigAlgName})"

      val isWeakKey =
        (pubKey is RSAPublicKey && keyBits in 1 until 2048) ||
          cert.sigAlgName.uppercase(Locale.ROOT).contains("MD5") ||
          cert.sigAlgName.uppercase(Locale.ROOT).contains("SHA1")

      val normalizedSubject = subject.uppercase(Locale.ROOT)
      val isDebugCert =
        normalizedSubject.contains("ANDROID DEBUG") ||
          normalizedSubject.contains("CN=TESTKEY") ||
          sha256 in KNOWN_TEST_KEY_SHA256

      val multiSigners =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          packageInfo.signingInfo?.hasMultipleSigners() == true
        } else {
          signatures.size > 1
        }

      SignatureAnalysis(
        hasSignature = true,
        sha256Fingerprint = sha256,
        sha1Fingerprint = sha1,
        subject = subject,
        issuer = issuer,
        keyAlgorithmInfo = keyAlgDesc,
        keyBitLength = keyBits,
        sigAlgName = cert.sigAlgName,
        validFromMillis = cert.notBefore.time,
        validUntilMillis = cert.notAfter.time,
        isDebugCert = isDebugCert,
        isExpired = isExpired,
        isSelfSigned = isSelfSigned,
        isWeakKey = isWeakKey,
        hasMultipleSigners = multiSigners,
      )
    } catch (_: Exception) {
      SignatureAnalysis(
        hasSignature = true,
        sha256Fingerprint = sha256,
        sha1Fingerprint = sha1,
        subject = "Certificado X.509 malformado",
        issuer = "Desconhecido",
        keyAlgorithmInfo = "Inválido",
        keyBitLength = 0,
        sigAlgName = "Inválido",
        validFromMillis = 0L,
        validUntilMillis = 0L,
        isDebugCert = false,
        isExpired = true,
        isSelfSigned = false,
        isWeakKey = true,
        hasMultipleSigners = signatures.size > 1,
      )
    }
  }

  @Suppress("DEPRECATION")
  private fun extractSignatures(packageInfo: PackageInfo): List<Signature> {
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      val signingInfo = packageInfo.signingInfo ?: return emptyList()
      val arr =
        if (signingInfo.hasMultipleSigners()) signingInfo.apkContentsSigners
        else signingInfo.signingCertificateHistory
      arr?.toList().orEmpty()
    } else {
      packageInfo.signatures?.toList().orEmpty()
    }
  }

  private fun digestHex(bytes: ByteArray, algorithm: String): String {
    val digest = MessageDigest.getInstance(algorithm).digest(bytes)
    return digest.joinToString(":") { b -> "%02X".format(Locale.ROOT, b) }
  }
}
