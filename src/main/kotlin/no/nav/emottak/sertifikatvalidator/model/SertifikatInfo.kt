package no.nav.emottak.sertifikatvalidator.model

import no.nav.emottak.sertifikatvalidator.util.formatDate
import no.nav.emottak.sertifikatvalidator.util.getSEIDVersion
import java.security.cert.X509Certificate

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
) {
    constructor(certificate: X509Certificate,
                status: SertifikatStatus,
                type: SertifikatType,
                orgnummer: String?,
                fnr: String?,
                beskrivelse: String,
                feilmelding: String?) : this(
            serienummer = certificate.serialNumber.toString(),
            status = status,
            type = type,
            seid = getSEIDVersion(certificate),
            gyldigFra = formatDate(certificate.notBefore),
            gyldigTil = formatDate(certificate.notAfter),
            utsteder = certificate.issuerX500Principal.name,
            orgnummer = orgnummer,
            fnr = fnr,
            beskrivelse = beskrivelse,
            feilmelding = feilmelding
        )
}
