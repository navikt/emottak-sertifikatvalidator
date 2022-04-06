package no.nav.emottak.sertifikatvalidator.model

data class ServerStatus(
    val status: String,
    val beskrivelse: String,
    val kompatibel: Boolean,
    val version: String
)
