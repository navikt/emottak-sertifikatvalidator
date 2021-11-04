package no.nav.emottak.sertifikatvalidator.util

import no.nav.emottak.sertifikatvalidator.FEIL_X509CERTIFICATE
import no.nav.emottak.sertifikatvalidator.model.KeyUsage
import no.nav.emottak.sertifikatvalidator.model.SEIDVersion
import no.nav.emottak.sertifikatvalidator.model.SertifikatError
import no.nav.emottak.sertifikatvalidator.util.KeyStoreHandler.Companion.getCertificateChain
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Object
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.DLTaggedObject
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.springframework.http.HttpStatus
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.regex.Pattern
import javax.naming.InvalidNameException
import javax.naming.ldap.LdapName
import javax.naming.ldap.Rdn
import javax.security.auth.x500.X500Principal


private const val POLICY_ID = "2.5.29.32"
private const val POLICY_ID_AGENCY = "[2.16.578.1.26.1.0.3.2]" //2.16.578.1.26.1.3.2

private val DN_TYPES_IN_SEARCHORDER = arrayOf("ou", "serialnumber", "OID.2.5.4.5", "o")
private val EXTRACT_ORGNO_PATTERN = Pattern.compile("^(\\d{9})$|^.*-\\s*(\\d{9})$")

internal fun getOrganizationNumber(x509Certificate: X509Certificate): String? {
    return if (isVirksomhetssertifikat(x509Certificate))
        getOrganizationNumberFromDN(x509Certificate.subjectX500Principal.getName(X500Principal.RFC1779))
    else
        null
}

private fun getOrganizationNumberFromDN(dn: String): String {
    try {
        val name: LdapName = newLdapName(dn)
        DN_TYPES_IN_SEARCHORDER.forEach { type ->
            val number = getOrganizationNumberFromRDN(name.rdns, type)
            if (number != null) return number
        }
    } catch (e: Exception) {
        return ""
    }
    return ""
}

private fun newLdapName(name: String): LdapName {
    return try {
        LdapName(name)
    } catch (e: InvalidNameException) {
        throw SertifikatError(HttpStatus.BAD_REQUEST, "failed to create LdapName", e)
    }
}

private fun getOrganizationNumberFromRDN(rdns: List<Rdn>, type: String): String? {
    rdns.forEach { rdn ->
        if (type.equals(rdn.type, ignoreCase = true)) {
            val matcher = EXTRACT_ORGNO_PATTERN.matcher(rdn.value as String)
            if (matcher.matches()) {
                return if (matcher.group(2) != null) matcher.group(2) else matcher.group(1)
            }
        }
    }
    return null
}

internal fun getSEIDVersion(certificate: X509Certificate): SEIDVersion {
    val serialNumberOID = "OID.2.5.4.5"
    val organizationIdentifierOID = "OID.2.4.5.97"

    val subject = newLdapName(certificate.subjectX500Principal.getName(X500Principal.RFC1779))

    if (isVirksomhetssertifikat(certificate)) {
        subject.rdns.firstOrNull { rdn -> rdn.type.equals(organizationIdentifierOID) }?.let { return SEIDVersion.SEID20 }
        return SEIDVersion.SEID10
    }
    else {
        subject.rdns.firstOrNull { rdn -> rdn.type.equals(serialNumberOID, ignoreCase = true) }?.let { rdn ->
            return if ((rdn.value as String?)?.startsWith("UN:NO", ignoreCase = true) == true) {
                SEIDVersion.SEID20
            } else {
                SEIDVersion.SEID10
            }
        }
    }
    return SEIDVersion.UKJENT
}

internal fun isVirksomhetssertifikat(x509Certificate: X509Certificate): Boolean {
    return getExtensionValue(x509Certificate, POLICY_ID).contains(POLICY_ID_AGENCY)
}

private fun getExtensionValue(x509Certificate: X509Certificate, oid: String): List<String> {
    val extensionValue = x509Certificate.getExtensionValue(oid)
    if (extensionValue != null) {
        var derObject = toDERObject(extensionValue)
        if (derObject is DEROctetString) {
            derObject = toDERObject(derObject.octets)
            if (derObject is DLSequence) {
                return derObject.objects.toList().map { it.toString() }
            }
        }
    }
    return emptyList()
}

internal fun isSelfSigned(certificate: X509Certificate) =
    certificate.subjectX500Principal == certificate.issuerX500Principal

private fun toDERObject(data: ByteArray): ASN1Primitive {
    val inStream = ByteArrayInputStream(data)
    val asnInputStream = ASN1InputStream(inStream)
    return asnInputStream.readObject()
}

internal fun createX509Certificate(certificateInputStream: InputStream): X509Certificate {
    val cf = CertificateFactory.getInstance("X.509")
    return try {
        cf.generateCertificate(certificateInputStream) as X509Certificate
    }
    catch (e: CertificateException) {
        throw SertifikatError(HttpStatus.BAD_REQUEST, FEIL_X509CERTIFICATE)
    }
}

fun getAuthorityInfoAccess(certificate: X509Certificate, method: ASN1ObjectIdentifier): String {
    val obj = getExtension(certificate, Extension.authorityInfoAccess.id) ?: return ""
    val accessDescriptions = obj as ASN1Sequence //ASN1Sequence.getInstance(obj)
    accessDescriptions.forEach {
        val accessDescription = it as ASN1Sequence
        if (accessDescription.size() == 2) {
            val identifier = accessDescription.getObjectAt(0) as ASN1ObjectIdentifier
            if (method.equals(identifier)) {
                return getStringFromGeneralName(accessDescription.getObjectAt(1) as ASN1Object)
            }
        }
    }
    return ""
}

internal fun getAuthorityInfoAccessObject(certificate: X509Certificate): ASN1Object? {
    var aia = getExtension(certificate, Extension.authorityInfoAccess.id)
    val certificateChain = getCertificateChain(certificate.subjectX500Principal.name)
    var i = 0
    while (aia == null && i < certificateChain.size) {
        aia = getExtension(certificateChain[i].toASN1Structure() as X509Certificate, Extension.authorityInfoAccess.id)
        i++
    }
    return aia
}

internal fun getStringFromGeneralName(names: ASN1Object): String {
    val taggedObject = names as DLTaggedObject
    return String(ASN1OctetString.getInstance(taggedObject, false).octets)
}

fun getExtension(certificate: X509Certificate, oid: String): ASN1Primitive? {
    val value = certificate.getExtensionValue(oid)
    return if (value == null) {
        null
    } else {
        val ap = JcaX509ExtensionUtils.parseExtensionValue(value)
        ASN1Sequence.getInstance(ap.encoded)
    }
}

//TODO
internal fun hasKeyUsage(certificate: X509Certificate, keyUsage: KeyUsage): Boolean {
    return getKeyUsages(certificate).contains(keyUsage)
}

private fun getKeyUsages(certificate: X509Certificate): List<KeyUsage> {
    val usage = certificate.keyUsage
    val keyUsageList = mutableListOf<KeyUsage>()
    if (usage != null && usage.isNotEmpty()) {
        KeyUsage.values().forEach {
            if (usage[it.ordinal]) {
                keyUsageList.add(it)
            }
        }
    }
    return keyUsageList
}
