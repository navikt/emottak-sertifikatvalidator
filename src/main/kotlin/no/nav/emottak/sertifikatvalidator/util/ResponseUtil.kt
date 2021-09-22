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

internal fun sertifikatSelvsignert(certificate: X509Certificate) =
    createSertifikatInfoFromX509Certificate(certificate, SertifikatStatus.FEIL_MED_SERTIFIKAT, SERTIFIKAT_SELF_SIGNED)

internal fun sertifikatIkkeGyldigEnda(certificate: X509Certificate) =
    createSertifikatInfoFromX509Certificate(certificate, SertifikatStatus.UTGAATT, SERTIFIKAT_IKKE_GYLDIG_ENDA)

internal fun sertifikatUtloept(certificate: X509Certificate) =
    createSertifikatInfoFromX509Certificate(certificate, SertifikatStatus.UTGAATT, SERTIFIKAT_IKKE_GYLDIG_LENGER)

internal fun sertifikatOK(certificate: X509Certificate, ssn: String) =
    createSertifikatInfoFromX509Certificate(certificate, SertifikatStatus.OK, SERTIFIKAT_VALIDERING_OK, ssn)

internal fun sertifikatOK(certificate: X509Certificate) =
    createSertifikatInfoFromX509Certificate(certificate, SertifikatStatus.OK, SERTIFIKAT_VALIDERING_OK, null)

internal fun createSertifikatInfoFromX509Certificate(x509Certificate: X509Certificate, status: SertifikatStatus, beskrivelse: String) =
    createSertifikatInfoFromX509Certificate(x509Certificate, status, beskrivelse, null)

internal fun createSertifikatInfoFromX509Certificate(x509Certificate: X509Certificate, status: SertifikatStatus, beskrivelse: String, ssn: String?) =
    if (getSertifikatType(x509Certificate) == SertifikatType.VIRKSOMHET) {
        createVirksomhetssertifikatInfo(x509Certificate, status, beskrivelse)
    }
    else {
        createPersonSertifikatInfo(x509Certificate, status, beskrivelse, ssn)
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

private fun getSertifikatType(x509Certificate: X509Certificate): SertifikatType {
    return if (isVirksomhetssertifikat(x509Certificate))
        SertifikatType.VIRKSOMHET
    else
        SertifikatType.PERSONLIG
}