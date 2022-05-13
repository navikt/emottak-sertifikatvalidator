package no.nav.emottak.sertifikatvalidator.model

import org.bouncycastle.asn1.x500.X500Name
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.ConstructorBinding
import java.security.cert.X509CRL
import java.time.LocalDateTime
import java.time.ZoneId

@ConstructorBinding
@ConfigurationProperties(prefix = "ekstern")
data class CertificateAuthorities (
    val caList: List<CAHolder>
)
data class CAHolder(
    val name: String,
    val dn: String,
    val crlUrl: String,
    val ocspUrl: String,
    val x500Name: X500Name = X500Name(dn),
    var crl: X509CRL?,
    var cachedDate: LocalDateTime = LocalDateTime.now()
)

data class CRLStatus(
    val name: String,
    val dn: String,
    val crlUrl: String,
    val ocspUrl: String,
    val cachedDate: LocalDateTime,
    val updatedDate: LocalDateTime
) {
    constructor(CAHolder: CAHolder) : this(
        name = CAHolder.name,
        dn = CAHolder.dn,
        crlUrl = CAHolder.crlUrl,
        ocspUrl = CAHolder.ocspUrl,
        cachedDate = CAHolder.cachedDate,
        updatedDate = CAHolder.crl?.thisUpdate?.toInstant()
            ?.atZone(ZoneId.systemDefault())
            ?.toLocalDateTime() ?: LocalDateTime.MIN
    )
}