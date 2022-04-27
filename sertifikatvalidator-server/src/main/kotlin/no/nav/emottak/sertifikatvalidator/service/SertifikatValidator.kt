package no.nav.emottak.sertifikatvalidator.service

import no.nav.emottak.sertifikatvalidator.ALL_REVOCATION_CHECKS_DISABLED
import no.nav.emottak.sertifikatvalidator.OCSP_VERIFICATION_UKJENT_FEIL
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_GYLDIG
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_GYLDIG_ENDA
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_GYLDIG_LENGER
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_SELF_SIGNED
import no.nav.emottak.sertifikatvalidator.UKJENT_FEIL
import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.SertifikatData
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
import java.time.Instant
import java.util.Date

@Service
class SertifikatValidator(val ocspChecker: OCSPChecker, val crlChecker: CRLChecker, val ssnCache: SsnCache) {


    internal fun validateCertificate(sertifikatData: SertifikatData, dateInstant: Instant): SertifikatInfo {
        log.info("UUID ${sertifikatData.uuid}, Serienummer ${sertifikatData.sertifikat.serialNumber}: sertifikatvalidering startet")
        log.debug(sertifikatData.sertifikat.toString())
        try {
            sjekkOmSertifikatErSelvsignert(sertifikatData)

            val certificateValidNow = certificateValidAtTime(sertifikatData, Instant.now())
            val certificateValidAtGivenTime = certificateValidAtTime(sertifikatData, dateInstant)
            return if (!certificateValidNow && !certificateValidAtGivenTime) {
                throw SertifikatError(HttpStatus.UNPROCESSABLE_ENTITY, SERTIFIKAT_IKKE_GYLDIG, sertifikatUtloept(sertifikatData), false)
            } else if (!certificateValidNow) {
                checkLegacyCertificate(sertifikatData)
            } else {
                checkCurrentCertificate(sertifikatData)
            }

        } catch (e: CertificateExpiredException) {
            throw SertifikatError(HttpStatus.UNPROCESSABLE_ENTITY, SERTIFIKAT_IKKE_GYLDIG_LENGER, sertifikatUtloept(sertifikatData), e)
        } catch (e: CertificateNotYetValidException) {
            throw SertifikatError(HttpStatus.UNPROCESSABLE_ENTITY, SERTIFIKAT_IKKE_GYLDIG_ENDA, sertifikatIkkeGyldigEnda(sertifikatData), e)
        }
    }

    private fun checkCurrentCertificate(sertifikatData: SertifikatData): SertifikatInfo {
        return sjekkSertifikat(sertifikatData = sertifikatData, sjekkCRL = true, sjekkOCSP = true)
    }

    private fun checkLegacyCertificate(sertifikatData: SertifikatData): SertifikatInfo {
        return sjekkSertifikat(sertifikatData = sertifikatData, sjekkCRL = false, sjekkOCSP = true)
    }

    private fun certificateValidAtTime(sertifikatData: SertifikatData, instant: Instant): Boolean {
        val certificate = sertifikatData.sertifikat
        return try {
            certificate.checkValidity(Date(instant.toEpochMilli()))
            true
        } catch (e: CertificateExpiredException) {
            false
        } catch (e: CertificateNotYetValidException) {
            false
        }
    }

    private fun sjekkSertifikat(sertifikatData: SertifikatData, sjekkCRL: Boolean, sjekkOCSP: Boolean): SertifikatInfo {
        if (!sjekkCRL && !sjekkOCSP) {
            throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, ALL_REVOCATION_CHECKS_DISABLED, sertifikatUkjentFeil(sertifikatData))
        }
        return if (isVirksomhetssertifikat(sertifikatData.sertifikat)) {
            sjekkVirksomhetssertifikat(sertifikatData, sjekkCRL, sjekkOCSP)
        } else {
            sjekkPersonligSertifikat(sertifikatData, sjekkCRL, sjekkOCSP)
        }
    }

    private fun sjekkOmSertifikatErSelvsignert(sertifikatData: SertifikatData) {
        if (isSelfSigned(sertifikatData.sertifikat)) {
            throw SertifikatError(HttpStatus.UNPROCESSABLE_ENTITY, SERTIFIKAT_SELF_SIGNED, sertifikatSelvsignert(sertifikatData), false)
        }
    }

    private fun sjekkPersonligSertifikat(sertifikatData: SertifikatData, sjekkCRL: Boolean, sjekkOCSP: Boolean): SertifikatInfo {
        log.debug("UUID ${sertifikatData.uuid}, Sertifikat: ${sertifikatData.sertifikat.serialNumber}: Personlig sertifikat, sjekkCRL: $sjekkCRL, sjekkOCSP: $sjekkOCSP")
        val ssn = ssnCache.getSSN(sertifikatData.sertifikat)
        if (ssn == null || !sjekkCRL) {
            log.info("SSN finnes ikke i cache, sjekker OCSP")
            return try {
                sjekkOCSP(sertifikatData)
            }
            catch (e: Exception) {
                if(sjekkCRL) {
                    log.info("OCSP sjekk feilet, sjekker CRL")
                    sjekkCRL(sertifikatData, null)
                }
                else {
                    log.info("OCSP sjekk feilet, men skipper backup CRL-sjekk fordi sjekkCRL = $sjekkCRL")
                    throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, OCSP_VERIFICATION_UKJENT_FEIL, sertifikatOCSPValideringFeilet(sertifikatData))
                }
            }
        } else {
            log.info("SSN finnes i cache, sjekkCRL = $sjekkCRL, sjekkOCSP = $sjekkOCSP")
            return if (sjekkCRL) {
                sjekkCRL(sertifikatData, ssn)
            }
            else {
                sjekkOCSP(sertifikatData)
            }
        }
    }

    private fun sjekkCRL(sertifikatData: SertifikatData, ssn: String?): SertifikatInfo {
        val sertifikat = sertifikatData.sertifikat
        try {
            val crlRevocationInfo =
                crlChecker.getCRLRevocationInfo(sertifikat.issuerX500Principal.name, sertifikat.serialNumber)
            if (crlRevocationInfo.revoked) {
                log.info("Sertifikat: ${sertifikat.serialNumber}: Sertifikat revokert (CRL)")
                return sertifikatRevokert(sertifikatData, crlRevocationInfo.revocationReason)
            }
            return sertifikatOK(sertifikatData, ssn)
        } catch (e: Exception) {
            val crlDistributionPoint = sertifikat.getExtensionValue(Extension.cRLDistributionPoints.toString())
            val crlDistributionPoints = CRLDistPoint.getInstance(JcaX509ExtensionUtils.parseExtensionValue(crlDistributionPoint))
            log.info("-------------------------------------------------")
            log.info("CRL sjekk feilet, muligens manglende CRL cache for issuer")
            log.info("Dersom dette ikke skulle feilet, vurder å oppdatere application properties med disse verdiene")
            log.info("DN: ${sertifikat.issuerX500Principal.name}")
            crlDistributionPoints.distributionPoints.forEach {
                log.info("CRL: ${it.distributionPoint.name}")
            }
            log.info("-------------------------------------------------")
            throw e
        }
    }

    private fun sjekkOCSP(sertifikatData: SertifikatData): SertifikatInfo {
        val sertifikat = sertifikatData.sertifikat
        val ocspResponse = ocspChecker.getOCSPStatus(sertifikatData)
        val fnr = ocspResponse.fnr
        if (!fnr.isNullOrBlank()) {
            ssnCache.updateSSNCacheValue(sertifikat, fnr)
        }
        if (ocspResponse.status == SertifikatStatus.REVOKERT) {
            log.info("UUID ${sertifikatData.uuid}, Sertifikat: ${sertifikat.serialNumber}: Sertifikat revokert (OCSP)")
            return ocspResponse
        }
        return sertifikatOK(sertifikatData, fnr)
    }

    private fun sjekkVirksomhetssertifikat(sertifikatData: SertifikatData, sjekkCRL: Boolean, sjekkOCSP: Boolean): SertifikatInfo {
        val sertifikat = sertifikatData.sertifikat
        log.debug("UUID ${sertifikatData.uuid}, Sertifikat: ${sertifikat.serialNumber}: Virksomhetssertifikat, sjekkCRL: $sjekkCRL, sjekkOCSP: $sjekkOCSP")
        return try {
            if(sjekkCRL)
                sjekkCRL(sertifikatData, null)
            else
                sjekkOCSP(sertifikatData)
        } catch (e: Exception) {
            log.warn("UUID ${sertifikatData.uuid}, Sertifikat: ${sertifikat.serialNumber}: Sjekk av CRL feilet, sjekker OCSP", e)
            if (sjekkOCSP) sjekkOCSP(sertifikatData) else throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, UKJENT_FEIL, sertifikatUkjentFeil(sertifikatData))
        }
    }
}


