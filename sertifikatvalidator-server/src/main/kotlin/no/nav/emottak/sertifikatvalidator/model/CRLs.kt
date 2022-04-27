package no.nav.emottak.sertifikatvalidator.model

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.ConstructorBinding
import java.security.cert.X509CRL
import java.time.LocalDateTime

@ConstructorBinding
@ConfigurationProperties(prefix = "ekstern")
data class CRLs (
    val crlList: List<CRLHolder>
)
data class CRLHolder(
    val name: String,
    val dn: String,
    val url: String,
    var crl: X509CRL?,
    var updatedDate: LocalDateTime = LocalDateTime.now()
)

data class CRLStatus(
    val name: String,
    val dn: String,
    val url: String,
    val updatedDate: LocalDateTime
) {
    constructor(crlHolder: CRLHolder) : this(
        name = crlHolder.name,
        dn = crlHolder.dn,
        url = crlHolder.url,
        updatedDate = crlHolder.updatedDate
    )
}