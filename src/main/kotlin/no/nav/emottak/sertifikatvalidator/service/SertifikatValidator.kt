package no.nav.emottak.sertifikatvalidator.service

import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_GYLDIG_ENDA
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_GYLDIG_LENGER
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_SELF_SIGNED
import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.SertifikatError
import no.nav.emottak.sertifikatvalidator.model.SertifikatInfo
import no.nav.emottak.sertifikatvalidator.model.SertifikatStatus
import no.nav.emottak.sertifikatvalidator.util.isSelfSigned
import no.nav.emottak.sertifikatvalidator.util.isVirksomhetssertifikat
import no.nav.emottak.sertifikatvalidator.util.sertifikatIkkeGyldigEnda
import no.nav.emottak.sertifikatvalidator.util.sertifikatOK
import no.nav.emottak.sertifikatvalidator.util.sertifikatRevokert
import no.nav.emottak.sertifikatvalidator.util.sertifikatSelvsignert
import no.nav.emottak.sertifikatvalidator.util.sertifikatUtloept
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Service
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Date

@Service
class SertifikatValidator(val ocspChecker: OCSPChecker, val crlChecker: CRLChecker, val ssnCache: SsnCache) {


    internal fun validateCertificate(certificate: X509Certificate, dateInstant: Instant): SertifikatInfo {
        log.debug(certificate.toString())
        try {
            certificate.checkValidity(Date(dateInstant.toEpochMilli()))
            sjekkOmSertifikatErSelvsignert(certificate)

            return sjekkSertifikat(certificate)
        } catch (e: CertificateExpiredException) {
            throw SertifikatError(HttpStatus.BAD_REQUEST, SERTIFIKAT_IKKE_GYLDIG_LENGER, sertifikatUtloept(certificate), e)
        } catch (e: CertificateNotYetValidException) {
            throw SertifikatError(HttpStatus.BAD_REQUEST, SERTIFIKAT_IKKE_GYLDIG_ENDA, sertifikatIkkeGyldigEnda(certificate), e)
        }
    }

    private fun sjekkSertifikat(certificate: X509Certificate): SertifikatInfo {
        return if (isVirksomhetssertifikat(certificate)) {
            sjekkVirksomhetssertifikat(certificate)
        } else {
            sjekkPersonligSertifikat(certificate)
        }
    }

    private fun sjekkOmSertifikatErSelvsignert(certificate: X509Certificate) {
        if (isSelfSigned(certificate)) {
            throw SertifikatError(HttpStatus.BAD_REQUEST, SERTIFIKAT_SELF_SIGNED, sertifikatSelvsignert(certificate))
        }
    }

    private fun sjekkPersonligSertifikat(certificate: X509Certificate): SertifikatInfo {
        val ssn = ssnCache.getSSN(certificate)
        if (ssn == null) {
            log.info("SSN finnes ikke i cache, sjekker OCSP")
            return try {
                sjekkOCSP(certificate)
            }
            catch (e: Exception) {
                log.info("OCSP sjekk feilet, sjekker CRL")
                sjekkCRL(certificate, null)
            }
        } else {
            log.info("SSN finnes i cache, sjekker CRL istedenfor")
            return sjekkCRL(certificate, ssn)
        }
    }

    private fun sjekkCRL(
        certificate: X509Certificate,
        ssn: String?
    ): SertifikatInfo {
        val crlRevocationInfo =
            crlChecker.getCRLRevocationInfo(certificate.issuerX500Principal.name, certificate.serialNumber)
        if (crlRevocationInfo.revoked) {
            return sertifikatRevokert(certificate, crlRevocationInfo.revocationReason)
        }
        return sertifikatOK(certificate, ssn)
    }

    private fun sjekkOCSP(certificate: X509Certificate): SertifikatInfo {
        val ocspResponse = ocspChecker.getOCSPStatus(certificate)
        val fnr = ocspResponse.fnr
        if (!fnr.isNullOrBlank()) {
            ssnCache.updateSSNCacheValue(certificate, fnr)
        }
        if (ocspResponse.status == SertifikatStatus.REVOKERT) {
            return ocspResponse
        }
        return sertifikatOK(certificate, fnr)
    }

    private fun sjekkVirksomhetssertifikat(certificate: X509Certificate): SertifikatInfo {
        log.info("Sertifikat: ${certificate.serialNumber}: Virksomhetssertifikat, sjekker CRL")
        try {
            val crlRevocationInfo = crlChecker.getCRLRevocationInfo(
                certificate.issuerX500Principal.name,
                certificate.serialNumber
            )
            if (crlRevocationInfo.revoked) {
                log.info("Sertifikat: ${certificate.serialNumber}: Sertifikat revokert (CRL)")
                return sertifikatRevokert(certificate, crlRevocationInfo.revocationReason)
            }
        } catch (e: Exception) {
            log.warn("Sertifikat: ${certificate.serialNumber}: Sjekk av CRL feilet, sjekker OCSP", e)
            val ocspResponse = ocspChecker.getOCSPStatus(certificate)
            if (ocspResponse.status == SertifikatStatus.REVOKERT) {
                log.info("Sertifikat: ${certificate.serialNumber}: Sertifikat revokert (OCSP)")
                return ocspResponse
            }
        }
        return sertifikatOK(certificate)
    }
}


