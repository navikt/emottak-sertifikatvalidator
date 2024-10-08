package no.nav.emottak.sertifikatvalidator.util

import net.logstash.logback.marker.Markers.appendEntries
import no.nav.emottak.sertifikatvalidator.CERTIFICATE_ISSUER_UNKNOWN
import no.nav.emottak.sertifikatvalidator.OCSP_VERIFICATION_UKJENT_FEIL
import no.nav.emottak.sertifikatvalidator.REVOKASJON_STATUS_FEILET
import no.nav.emottak.sertifikatvalidator.REVOKASJON_STATUS_MANGLER
import no.nav.emottak.sertifikatvalidator.REVOKASJON_STATUS_UKJENT
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_GYLDIG_ENDA
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_GYLDIG_LENGER
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_REVOKERT
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_REVOKERT
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_SELF_SIGNED
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_VALIDERING_OK
import no.nav.emottak.sertifikatvalidator.UKJENT_FEIL
import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.RevocationReason
import no.nav.emottak.sertifikatvalidator.model.SEIDVersion
import no.nav.emottak.sertifikatvalidator.model.SertifikatData
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
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale


internal fun createResponseEntity(sertifikatInfo: SertifikatInfo, uuid: String, inkluderFnr: Boolean): ResponseEntity<SertifikatInfo> {
    return when(sertifikatInfo.status) {
        SertifikatStatus.OK -> createResponseEntity(HttpStatus.OK, sertifikatInfo, uuid, inkluderFnr)
        SertifikatStatus.FEIL_MED_INPUT -> createResponseEntity(HttpStatus.BAD_REQUEST, sertifikatInfo, uuid)
        SertifikatStatus.UTGAATT -> createResponseEntity(HttpStatus.UNPROCESSABLE_ENTITY, sertifikatInfo, uuid)
        SertifikatStatus.REVOKERT -> createResponseEntity(HttpStatus.UNPROCESSABLE_ENTITY, sertifikatInfo, uuid)
        SertifikatStatus.FEIL_MED_SERTIFIKAT -> createResponseEntity(HttpStatus.UNPROCESSABLE_ENTITY, sertifikatInfo, uuid)
        SertifikatStatus.FEIL_MED_TJENESTEN -> createResponseEntity(HttpStatus.INTERNAL_SERVER_ERROR, sertifikatInfo, uuid)
        SertifikatStatus.UKJENT -> createResponseEntity(HttpStatus.INTERNAL_SERVER_ERROR, sertifikatInfo, uuid)
    }
}

private fun createResponseEntity(httpStatus: HttpStatus, sertifikatInfo: SertifikatInfo, uuid: String, inkluderFnr: Boolean = false): ResponseEntity<SertifikatInfo> {
    log.info(appendEntries(createFieldMap(httpStatus, sertifikatInfo, uuid)), "Sertifikatvalidering response returnert")
    val filtrertSertifikatInfo = if (inkluderFnr) {
        sertifikatInfo
    } else {
        sertifikatInfo.copy(fnr = "***********")
    }
    return ResponseEntity.status(httpStatus).contentType(MediaType.APPLICATION_JSON).body(filtrertSertifikatInfo)
}

internal fun createFieldMap(httpStatus: HttpStatus, sertifikatInfo: SertifikatInfo?, uuid: String): Map<String, Any> {
    return mapOf(
        Pair("id", uuid),
        Pair("mottakId", uuid),
        Pair("statusCode", httpStatus.value()),
        Pair("status", sertifikatInfo?.status ?: SertifikatStatus.UKJENT),
        Pair("sertifikatSeid", sertifikatInfo?.seid ?: SEIDVersion.UKJENT),
        Pair("issuer", sertifikatInfo?.utsteder ?: "UKJENT"),
        Pair("sertifikatType", sertifikatInfo?.type ?: "UKJENT")
    )
}

internal fun createFieldMap(sertifikatData: SertifikatData): Map<String, Any> {
    return mapOf(
        Pair("id", sertifikatData.uuid),
        Pair("mottakId", sertifikatData.uuid)
    )
}

internal fun createFieldMap(uuid: String): Map<String, Any> {
    return mapOf(
        Pair("id", uuid),
        Pair("mottakId", uuid)
    )
}

internal fun sertifikatSelvsignert(sertifikatData: SertifikatData) =
    createSertifikatInfoFromCertificate(sertifikatData, SertifikatStatus.FEIL_MED_SERTIFIKAT, SERTIFIKAT_SELF_SIGNED)

internal fun sertifikatRevokert(sertifikatData: SertifikatData, revokeringsBeskrivelse: String) =
    createSertifikatInfoFromCertificate(sertifikatData, SertifikatStatus.REVOKERT, revokeringsBeskrivelse)

internal fun sertifikatIkkeGyldigEnda(sertifikatData: SertifikatData) =
    createSertifikatInfoFromCertificate(sertifikatData, SertifikatStatus.UTGAATT, SERTIFIKAT_IKKE_GYLDIG_ENDA)

internal fun sertifikatUtloept(sertifikatData: SertifikatData) =
    createSertifikatInfoFromCertificate(sertifikatData, SertifikatStatus.UTGAATT, SERTIFIKAT_IKKE_GYLDIG_LENGER)

internal fun sertifikatOCSPValideringFeilet(sertifikatData: SertifikatData) =
    createSertifikatInfoFromCertificate(sertifikatData, SertifikatStatus.UKJENT, OCSP_VERIFICATION_UKJENT_FEIL)

internal fun sertifikatOK(sertifikatData: SertifikatData, ssn: String?) =
    createSertifikatInfoFromCertificate(sertifikatData, SertifikatStatus.OK, SERTIFIKAT_VALIDERING_OK, ssn)

internal fun sertifikatOK(sertifikatData: SertifikatData) = sertifikatOK(sertifikatData, null)

internal fun sertifikatUkjentSertifikatUtsteder(sertifikatData: SertifikatData) =
    createSertifikatInfoFromCertificate(sertifikatData, SertifikatStatus.FEIL_MED_SERTIFIKAT, CERTIFICATE_ISSUER_UNKNOWN)
internal fun sertifikatUkjentFeil(sertifikatData: SertifikatData) =
    createSertifikatInfoFromCertificate(sertifikatData, SertifikatStatus.UKJENT, UKJENT_FEIL)

internal fun createSertifikatInfoFromCertificate(sertifikatData: SertifikatData, status: SertifikatStatus, beskrivelse: String) =
    createSertifikatInfoFromCertificate(sertifikatData, status, beskrivelse, null)

internal fun createSertifikatInfoFromCertificate(sertifikatData: SertifikatData, status: SertifikatStatus, beskrivelse: String, ssn: String?): SertifikatInfo {
    log.info(appendEntries(createFieldMap(sertifikatData)), "Sertifikatvalidering $status")
    return when (getSertifikatType(sertifikatData.sertifikat)) {
        SertifikatType.PERSONLIG -> createPersonSertifikatInfo(sertifikatData, status, beskrivelse, ssn)
        SertifikatType.VIRKSOMHET -> createVirksomhetssertifikatInfo(sertifikatData, status, beskrivelse)
    }
}

private fun createPersonSertifikatInfo(
    sertifikatData: SertifikatData,
    status: SertifikatStatus,
    beskrivelse: String,
    ssn: String?
) = SertifikatInfo(
    serienummer = sertifikatData.sertifikat.serialNumber.toString(),
    status = status,
    type = SertifikatType.PERSONLIG,
    seid = getSEIDVersion(sertifikatData.sertifikat),
    gyldigFra = formatDate(sertifikatData.sertifikat.notBefore),
    gyldigTil = formatDate(sertifikatData.sertifikat.notAfter),
    utsteder = sertifikatData.sertifikat.issuerX500Principal.name,
    orgnummer = null,
    fnr = ssn,
    beskrivelse = beskrivelse,
    feilmelding = null
)

private fun createVirksomhetssertifikatInfo(
    sertifikatData: SertifikatData,
    status: SertifikatStatus,
    beskrivelse: String
) = SertifikatInfo(
    serienummer = sertifikatData.sertifikat.serialNumber.toString(),
    status = status,
    type = SertifikatType.VIRKSOMHET,
    seid = getSEIDVersion(sertifikatData.sertifikat),
    gyldigFra = formatDate(sertifikatData.sertifikat.notBefore),
    gyldigTil = formatDate(sertifikatData.sertifikat.notAfter),
    utsteder = sertifikatData.sertifikat.issuerX500Principal.name,
    orgnummer = getOrganizationNumber(sertifikatData.sertifikat),
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
    when (certStatus) {
        null -> {
            status = SertifikatStatus.OK
            beskrivelse = SERTIFIKAT_IKKE_REVOKERT
        }
        is RevokedStatus -> {
            status = SertifikatStatus.REVOKERT
            beskrivelse = if (certStatus.hasRevocationReason()) {
                RevocationReason.getRevocationReason(certStatus.revocationReason)
            } else {
                REVOKASJON_STATUS_MANGLER
            }
            log.warn("$SERTIFIKAT_REVOKERT: $beskrivelse")
        }
        is UnknownStatus -> {
            log.warn(REVOKASJON_STATUS_UKJENT)
            beskrivelse = REVOKASJON_STATUS_UKJENT
        }
        else -> {
            log.warn(REVOKASJON_STATUS_FEILET)
            beskrivelse = REVOKASJON_STATUS_FEILET
        }
    }
    return SertifikatInfo(
        serienummer = certificate.serialNumber.toString(),
        status = status,
        type = getSertifikatType(certificate),
        seid = getSEIDVersion(certificate),
        gyldigFra = formatDate(certificate.notBefore),
        gyldigTil = formatDate(certificate.notAfter),
        utsteder = certificate.issuerX500Principal.name,
        orgnummer = getOrganizationNumber(certificate),
        fnr = ssn,
        beskrivelse = beskrivelse,
        feilmelding = null
    )
}

internal fun formatDate(date: Date): String {
    return SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale("nb")).format(date)
}

private fun getSertifikatType(certificate: X509Certificate): SertifikatType {
    return if (isVirksomhetssertifikat(certificate))
        SertifikatType.VIRKSOMHET
    else
        SertifikatType.PERSONLIG
}