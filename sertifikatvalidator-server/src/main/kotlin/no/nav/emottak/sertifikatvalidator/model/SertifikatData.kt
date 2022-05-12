package no.nav.emottak.sertifikatvalidator.model

import java.security.cert.X509Certificate
import java.time.Instant

data class SertifikatData(
    val sertifikat: X509Certificate,
    val uuid: String,
    val gyldighetsDato: Instant
)