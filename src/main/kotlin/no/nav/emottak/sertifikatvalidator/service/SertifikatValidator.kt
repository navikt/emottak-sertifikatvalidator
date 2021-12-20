package no.nav.emottak.sertifikatvalidator.service

import no.nav.emottak.sertifikatvalidator.ALL_REVOCATION_CHECKS_DISABLED
import no.nav.emottak.sertifikatvalidator.OCSP_VERIFICATION_UKJENT_FEIL
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_GYLDIG
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_GYLDIG_ENDA
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_GYLDIG_LENGER
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_SELF_SIGNED
import no.nav.emottak.sertifikatvalidator.UKJENT_FEIL
import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.SertifikatError
import no.nav.emottak.sertifikatvalidator.model.SertifikatInfo
import no.nav.emottak.sertifikatvalidator.model.SertifikatStatus
import no.nav.emottak.sertifikatvalidator.util.isSelfSigned
import no.nav.emottak.sertifikatvalidator.util.isVirksomhetssertifikat
import no.nav.emottak.sertifikatvalidator.util.sertifikatIkkeGyldigEnda
import no.nav.emottak.sertifikatvalidator.util.sertifikatOCSPValideringFeilet
import no.nav.emottak.sertifikatvalidator.util.sertifikatOK
import no.nav.emottak.sertifikatvalidator.util.sertifikatRevokert
import no.nav.emottak.sertifikatvalidator.util.sertifikatSelvsignert
import no.nav.emottak.sertifikatvalidator.util.sertifikatUkjentFeil
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
            sjekkOmSertifikatErSelvsignert(certificate)

            val certificateValidNow = certificateValidAtTime(certificate, Instant.now())
            val certificateValidAtGivenTime = certificateValidAtTime(certificate, dateInstant)
            if (!certificateValidNow && !certificateValidAtGivenTime) {
                throw SertifikatError(HttpStatus.BAD_REQUEST, SERTIFIKAT_IKKE_GYLDIG, sertifikatUtloept(certificate))
            }
            else if (!certificateValidNow) {
                return checkLegacyCertificate(certificate)
            }
            else {
                return checkCurrentCertificate(certificate)
            }


        } catch (e: CertificateExpiredException) {
            throw SertifikatError(HttpStatus.BAD_REQUEST, SERTIFIKAT_IKKE_GYLDIG_LENGER, sertifikatUtloept(certificate), e)
        } catch (e: CertificateNotYetValidException) {
            throw SertifikatError(HttpStatus.BAD_REQUEST, SERTIFIKAT_IKKE_GYLDIG_ENDA, sertifikatIkkeGyldigEnda(certificate), e)
        }
    }

    private fun checkCurrentCertificate(certificate: X509Certificate): SertifikatInfo {
        //TODO return sjekkSertifikat(certificate = certificate, sjekkCRL = true, sjekkOCSP = true)
        return sjekkSertifikat(certificate = certificate, sjekkCRL = false, sjekkOCSP = false)
    }

    private fun checkLegacyCertificate(certificate: X509Certificate): SertifikatInfo {
        //TODO return sjekkSertifikat(certificate = certificate, sjekkCRL = false, sjekkOCSP = true)
        return sjekkSertifikat(certificate = certificate, sjekkCRL = false, sjekkOCSP = false)
    }

    private fun certificateValidAtTime(certificate: X509Certificate, instant: Instant): Boolean {
        return try {
            certificate.checkValidity(Date(instant.toEpochMilli()))
            true
        } catch (e: CertificateExpiredException) {
            false
        } catch (e: CertificateNotYetValidException) {
            false
        }
    }

    private fun sjekkSertifikat(certificate: X509Certificate, sjekkCRL: Boolean, sjekkOCSP: Boolean): SertifikatInfo {
        if (!sjekkCRL && !sjekkOCSP) {
            throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, ALL_REVOCATION_CHECKS_DISABLED, sertifikatUkjentFeil(certificate))
        }
        return if (isVirksomhetssertifikat(certificate)) {
            sjekkVirksomhetssertifikat(certificate, sjekkCRL, sjekkOCSP)
        } else {
            sjekkPersonligSertifikat(certificate, sjekkCRL, sjekkOCSP)
        }
    }

    private fun sjekkOmSertifikatErSelvsignert(certificate: X509Certificate) {
        if (isSelfSigned(certificate)) {
            throw SertifikatError(HttpStatus.BAD_REQUEST, SERTIFIKAT_SELF_SIGNED, sertifikatSelvsignert(certificate))
        }
    }

    private fun sjekkPersonligSertifikat(certificate: X509Certificate, sjekkCRL: Boolean, sjekkOCSP: Boolean): SertifikatInfo {
        log.info("Sertifikat: ${certificate.serialNumber}: Personlig sertifikat, sjekkCRL: $sjekkCRL, sjekkOCSP: $sjekkOCSP")
        val ssn = ssnCache.getSSN(certificate)
        if (ssn == null || !sjekkCRL) {
            log.info("SSN finnes ikke i cache, sjekker OCSP")
            return try {
                sjekkOCSP(certificate)
            }
            catch (e: Exception) {
                log.warn("OCSP sjekk feilet", e)
                if(sjekkCRL) {
                    log.info("OCSP sjekk feilet, sjekker CRL")
                    sjekkCRL(certificate, null)
                }
                else {
                    log.info("OCSP sjekk feilet, men skipper backup CRL-sjekk fordi sjekkCRL = $sjekkCRL")
                    throw SertifikatError(HttpStatus.BAD_REQUEST, OCSP_VERIFICATION_UKJENT_FEIL, sertifikatOCSPValideringFeilet(certificate))
                }
            }
        } else {
            log.info("SSN finnes i cache, sjekkCRL = $sjekkCRL, sjekkOCSP = $sjekkOCSP")
            return if (sjekkCRL) {
                sjekkCRL(certificate, ssn)
            }
            else {
                sjekkOCSP(certificate)
            }
        }
    }

    private fun sjekkCRL(certificate: X509Certificate, ssn: String?): SertifikatInfo {
        val crlRevocationInfo =
            crlChecker.getCRLRevocationInfo(certificate.issuerX500Principal.name, certificate.serialNumber)
        if (crlRevocationInfo.revoked) {
            log.info("Sertifikat: ${certificate.serialNumber}: Sertifikat revokert (CRL)")
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
            log.info("Sertifikat: ${certificate.serialNumber}: Sertifikat revokert (OCSP)")
            return ocspResponse
        }
        return sertifikatOK(certificate, fnr)
    }

    private fun sjekkVirksomhetssertifikat(certificate: X509Certificate, sjekkCRL: Boolean, sjekkOCSP: Boolean): SertifikatInfo {
        log.info("Sertifikat: ${certificate.serialNumber}: Virksomhetssertifikat, sjekkCRL: $sjekkCRL, sjekkOCSP: $sjekkOCSP")
        return try {
            if(sjekkCRL)
                sjekkCRL(certificate, null)
            else
                sjekkOCSP(certificate)
        } catch (e: Exception) {
            log.warn("Sertifikat: ${certificate.serialNumber}: Sjekk av CRL feilet, sjekker OCSP", e)
            if (sjekkOCSP) sjekkOCSP(certificate) else throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, UKJENT_FEIL, sertifikatUkjentFeil(certificate))
        }
    }
}


