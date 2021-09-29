package no.nav.emottak.sertifikatvalidator.model

import java.math.BigInteger
import java.util.*

data class CRLRevocationInfo(
    val revoked: Boolean,
    val serialNumber: BigInteger,
    val sertificateIssuer: String? = null,
    val revocationDate: Date? = null,
    val revocationReason: String
)