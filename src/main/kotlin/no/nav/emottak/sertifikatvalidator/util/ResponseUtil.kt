package no.nav.emottak.sertifikatvalidator.util

import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.RevocationReason
import no.nav.emottak.sertifikatvalidator.model.SertifikatInfo
import no.nav.emottak.sertifikatvalidator.model.SertifikatStatus
import no.nav.emottak.sertifikatvalidator.model.SertifikatType
import org.bouncycastle.cert.ocsp.CertificateStatus
import org.bouncycastle.cert.ocsp.RevokedStatus
import org.bouncycastle.cert.ocsp.SingleResp
import org.bouncycastle.cert.ocsp.UnknownStatus
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

internal fun createSertifikatInfoFromOCSPResponse(
    certificate: X509Certificate,
    singleResponse: SingleResp,
    ssn: String
): SertifikatInfo {
    val certStatus: CertificateStatus? = singleResponse.certStatus
    var status = SertifikatStatus.UKJENT
    val beskrivelse: String
    if (certStatus == null) {
        status = SertifikatStatus.OK
        beskrivelse = "Certificate not revoked"
    } else if (certStatus is RevokedStatus) {
        status = SertifikatStatus.REVOKERT
        beskrivelse = if (certStatus.hasRevocationReason()) {
            RevocationReason.getRevocationReason(certStatus.revocationReason)
        } else {
            "Revokert, Ukjent årsak"
        }
        log.warn("Certificate is revoked: $beskrivelse")
    } else if (certStatus is UnknownStatus) {
        log.warn("certificate status unknown, could be revoked")
        beskrivelse = "certificate status unknown, could be revoked"
    } else {
        log.warn("can't establish certificate status, could be revoked")
        beskrivelse = "can't establish certificate status, could be revoked"
    }
    return SertifikatInfo(
        serienummer = certificate.serialNumber.toString(),
        status = status,
        type = getSertifikatType(certificate),
        utsteder = certificate.issuerX500Principal.name,
        orgnummer = getOrganizationNumber(certificate),
        fnr = ssn,
        beskrivelse = beskrivelse,
        feilmelding = null
    )
}

private fun getSertifikatType(x509Certificate: X509Certificate): SertifikatType {
    return if (isVirksomhetssertifikat(x509Certificate))
        SertifikatType.VIRKSOMHET
    else
        SertifikatType.PERSONLIG
}