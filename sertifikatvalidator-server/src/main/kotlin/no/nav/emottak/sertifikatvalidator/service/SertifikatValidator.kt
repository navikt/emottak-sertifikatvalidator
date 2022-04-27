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
import org.bouncycastle.asn1.x509.CRLDistPoint
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Service
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Date

@Service
class SertifikatValidator(val ocspChecker: OCSPChecker, val crlChecker: CRLChecker, val ssnCache: SsnCache) {


    internal fun validateCertificate(certificate: X509Certificate, dateInstant: Instant, uuid: String): SertifikatInfo {
        log.info("$uuid sertifikatvalidering startet")
        log.debug(certificate.toString())
        try {
            sjekkOmSertifikatErSelvsignert(certificate)

            val certificateValidNow = certificateValidAtTime(certificate, Instant.now())
            val certificateValidAtGivenTime = certificateValidAtTime(certificate, dateInstant)
            return if (!certificateValidNow && !certificateValidAtGivenTime) {
                log.warn("$uuid sertifikatvalidering feilet")
                throw SertifikatError(HttpStatus.UNPROCESSABLE_ENTITY, SERTIFIKAT_IKKE_GYLDIG, sertifikatUtloept(certificate), false)
            } else if (!certificateValidNow) {
                log.info("$uuid sertifikatvalidering sjekker legacy sertifikat")
                checkLegacyCertificate(certificate)
            } else {
                log.info("$uuid sertifikatvalidering sjekker aktivt sertifikat")
                checkCurrentCertificate(certificate)
            }

        } catch (e: CertificateExpiredException) {
            throw SertifikatError(HttpStatus.UNPROCESSABLE_ENTITY, SERTIFIKAT_IKKE_GYLDIG_LENGER, sertifikatUtloept(certificate), e)
        } catch (e: CertificateNotYetValidException) {
            throw SertifikatError(HttpStatus.UNPROCESSABLE_ENTITY, SERTIFIKAT_IKKE_GYLDIG_ENDA, sertifikatIkkeGyldigEnda(certificate), e)
        }
    }

    private fun checkCurrentCertificate(certificate: X509Certificate): SertifikatInfo {
        return sjekkSertifikat(certificate = certificate, sjekkCRL = true, sjekkOCSP = true)
    }

    private fun checkLegacyCertificate(certificate: X509Certificate): SertifikatInfo {
        return sjekkSertifikat(certificate = certificate, sjekkCRL = false, sjekkOCSP = true)
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
            throw SertifikatError(HttpStatus.UNPROCESSABLE_ENTITY, SERTIFIKAT_SELF_SIGNED, sertifikatSelvsignert(certificate), false)
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
                if(sjekkCRL) {
                    log.info("OCSP sjekk feilet, sjekker CRL")
                    sjekkCRL(certificate, null)
                }
                else {
                    log.info("OCSP sjekk feilet, men skipper backup CRL-sjekk fordi sjekkCRL = $sjekkCRL")
                    throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, OCSP_VERIFICATION_UKJENT_FEIL, sertifikatOCSPValideringFeilet(certificate))
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
        try {
            val crlRevocationInfo =
                crlChecker.getCRLRevocationInfo(certificate.issuerX500Principal.name, certificate.serialNumber)
            if (crlRevocationInfo.revoked) {
                log.info("Sertifikat: ${certificate.serialNumber}: Sertifikat revokert (CRL)")
                return sertifikatRevokert(certificate, crlRevocationInfo.revocationReason)
            }
            return sertifikatOK(certificate, ssn)
        } catch (e: Exception) {
            val crlDistributionPoint = certificate.getExtensionValue(Extension.cRLDistributionPoints.toString())
            val crlDistributionPoints = CRLDistPoint.getInstance(JcaX509ExtensionUtils.parseExtensionValue(crlDistributionPoint))
            log.info("-------------------------------------------------")
            log.info("CRL sjekk feilet, muligens manglende CRL cache for issuer")
            log.info("Dersom dette ikke skulle feilet, vurder å oppdatere application properties med disse verdiene")
            log.info("DN: ${certificate.issuerX500Principal.name}")
            crlDistributionPoints.distributionPoints.forEach {
                log.info("CRL: ${it.distributionPoint.name}")
            }
            log.info("-------------------------------------------------")
            throw e
        }
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


