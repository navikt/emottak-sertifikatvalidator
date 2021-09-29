package no.nav.emottak.sertifikatvalidator.util

import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_GYLDIG_ENDA
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_GYLDIG_LENGER
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_SELF_SIGNED
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_VALIDERING_OK
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
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import java.security.cert.X509Certificate


internal fun createResponseEntity(sertifikatInfo: SertifikatInfo): ResponseEntity<SertifikatInfo> {
    return when(sertifikatInfo.status) {
        SertifikatStatus.OK -> createResponseEntity(HttpStatus.OK, sertifikatInfo)
        SertifikatStatus.FEIL_MED_INPUT -> createResponseEntity(HttpStatus.BAD_REQUEST, sertifikatInfo)
        SertifikatStatus.UTGAATT -> createResponseEntity(HttpStatus.BAD_REQUEST, sertifikatInfo)
        SertifikatStatus.REVOKERT -> createResponseEntity(HttpStatus.BAD_REQUEST, sertifikatInfo)
        SertifikatStatus.FEIL_MED_SERTIFIKAT -> createResponseEntity(HttpStatus.BAD_REQUEST, sertifikatInfo)
        SertifikatStatus.FEIL_MED_TJENESTEN -> createResponseEntity(HttpStatus.INTERNAL_SERVER_ERROR, sertifikatInfo)
        SertifikatStatus.UKJENT -> createResponseEntity(HttpStatus.INTERNAL_SERVER_ERROR, sertifikatInfo)
    }
}

private fun createResponseEntity(httpStatus: HttpStatus, sertifikatInfo: SertifikatInfo) =
    ResponseEntity.status(httpStatus).contentType(MediaType.APPLICATION_JSON).body(sertifikatInfo)

internal fun sertifikatSelvsignert(certificate: X509Certificate) =
    createSertifikatInfoFromCertificate(certificate, SertifikatStatus.FEIL_MED_SERTIFIKAT, SERTIFIKAT_SELF_SIGNED)

internal fun sertifikatRevokert(certificate: X509Certificate, revokeringsBeskrivelse: String) =
    createSertifikatInfoFromCertificate(certificate, SertifikatStatus.REVOKERT, revokeringsBeskrivelse)

internal fun sertifikatIkkeGyldigEnda(certificate: X509Certificate) =
    createSertifikatInfoFromCertificate(certificate, SertifikatStatus.UTGAATT, SERTIFIKAT_IKKE_GYLDIG_ENDA)

internal fun sertifikatUtloept(certificate: X509Certificate) =
    createSertifikatInfoFromCertificate(certificate, SertifikatStatus.UTGAATT, SERTIFIKAT_IKKE_GYLDIG_LENGER)

internal fun sertifikatOK(certificate: X509Certificate, ssn: String?) =
    createSertifikatInfoFromCertificate(certificate, SertifikatStatus.OK, SERTIFIKAT_VALIDERING_OK, ssn)

internal fun sertifikatOK(certificate: X509Certificate) =
    createSertifikatInfoFromCertificate(certificate, SertifikatStatus.OK, SERTIFIKAT_VALIDERING_OK, null)

internal fun createSertifikatInfoFromCertificate(certificate: X509Certificate, status: SertifikatStatus, beskrivelse: String) =
    createSertifikatInfoFromCertificate(certificate, status, beskrivelse, null)

internal fun createSertifikatInfoFromCertificate(certificate: X509Certificate, status: SertifikatStatus, beskrivelse: String, ssn: String?) =
        if (getSertifikatType(certificate) == SertifikatType.VIRKSOMHET) {
            log.info("Sertifikat: ${certificate.serialNumber}, sertifikatstatus: $status")
            createVirksomhetssertifikatInfo(certificate, status, beskrivelse)
        } else {
            log.info("Sertifikat: ${certificate.serialNumber}, sertifikatstatus: $status")
            createPersonSertifikatInfo(certificate, status, beskrivelse, ssn)
        }

private fun createPersonSertifikatInfo(
    certificate: X509Certificate,
    status: SertifikatStatus,
    beskrivelse: String,
    ssn: String?
) = SertifikatInfo(
    serienummer = certificate.serialNumber.toString(),
    status = status,
    type = SertifikatType.PERSONLIG,
    utsteder = certificate.issuerX500Principal.name,
    orgnummer = null,
    fnr = ssn,
    beskrivelse = beskrivelse,
    feilmelding = null
)

private fun createVirksomhetssertifikatInfo(
    certificate: X509Certificate,
    status: SertifikatStatus,
    beskrivelse: String
) = SertifikatInfo(
    serienummer = certificate.serialNumber.toString(),
    status = status,
    type = SertifikatType.VIRKSOMHET,
    utsteder = certificate.issuerX500Principal.name,
    orgnummer = getOrganizationNumber(certificate),
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

private fun getSertifikatType(certificate: X509Certificate): SertifikatType {
    return if (isVirksomhetssertifikat(certificate))
        SertifikatType.VIRKSOMHET
    else
        SertifikatType.PERSONLIG
}