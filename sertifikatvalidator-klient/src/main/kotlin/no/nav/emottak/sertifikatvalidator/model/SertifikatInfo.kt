package no.nav.emottak.sertifikatvalidator.model

data class SertifikatInfo(
    val serienummer: String,
    val status: SertifikatStatus,
    val type: SertifikatType,
    val seid: SEIDVersion,
    val gyldigFra: String,
    val gyldigTil: String,
    val utsteder: String,
    val orgnummer: String? = null,
    val fnr: String? = null,
    val beskrivelse: String,
    val feilmelding: String? = null
)
