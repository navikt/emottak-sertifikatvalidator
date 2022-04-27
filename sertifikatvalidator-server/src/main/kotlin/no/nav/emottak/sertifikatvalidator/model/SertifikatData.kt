package no.nav.emottak.sertifikatvalidator.model

import java.security.cert.X509Certificate

data class SertifikatData(
    val sertifikat: X509Certificate,
    val uuid: String
)