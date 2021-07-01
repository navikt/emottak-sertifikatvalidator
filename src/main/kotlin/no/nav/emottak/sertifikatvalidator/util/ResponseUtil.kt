package no.nav.emottak.sertifikatvalidator.util

import no.nav.emottak.sertifikatvalidator.model.SertifikatInfo
import no.nav.emottak.sertifikatvalidator.model.SertifikatStatus
import no.nav.emottak.sertifikatvalidator.model.SertifikatType
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import java.security.cert.X509Certificate


internal fun createResponseEntity(sertifikatInfo: SertifikatInfo): ResponseEntity<SertifikatInfo> {
    return when(sertifikatInfo.status) {
        SertifikatStatus.OK -> ResponseEntity.ok(sertifikatInfo)
        SertifikatStatus.FEIL_MED_INPUT -> ResponseEntity.badRequest().body(sertifikatInfo)
        SertifikatStatus.UTGAATT -> ResponseEntity.badRequest().body(sertifikatInfo)
        SertifikatStatus.REVOKERT -> ResponseEntity.badRequest().body(sertifikatInfo)
        SertifikatStatus.FEIL_MED_SERTIFIKAT -> ResponseEntity.badRequest().body(sertifikatInfo)
        SertifikatStatus.FEIL_MED_TJENESTEN -> ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(sertifikatInfo)
        SertifikatStatus.UKJENT -> ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(sertifikatInfo)
    }
}

internal fun createSertifikatInfoFromX509Certificate(x509Certificate: X509Certificate, status: SertifikatStatus, beskrivelse: String) =
    SertifikatInfo(
        serienummer = x509Certificate.serialNumber.toString(),
        status = status,
        type = getSertifikatType(x509Certificate),
        utsteder = x509Certificate.issuerX500Principal.name,
        orgnummer = getOrganizationNumber(x509Certificate),
        fnr = null,
        beskrivelse = beskrivelse,
        feilmelding = null
    )

private fun getSertifikatType(x509Certificate: X509Certificate): SertifikatType {
    return if (isVirksomhetssertifikat(x509Certificate))
        SertifikatType.VIRKSOMHET
    else
        SertifikatType.PERSONLIG
}