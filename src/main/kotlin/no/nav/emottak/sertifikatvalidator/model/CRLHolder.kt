package no.nav.emottak.sertifikatvalidator.model

import org.bouncycastle.asn1.x500.X500Name
import java.security.cert.X509CRL
import java.time.LocalDateTime

data class CRLHolder(
    val dn: X500Name,
    val crlUrl: String,
    var crl: X509CRL,
    val updatedDate: LocalDateTime = LocalDateTime.now()
)
