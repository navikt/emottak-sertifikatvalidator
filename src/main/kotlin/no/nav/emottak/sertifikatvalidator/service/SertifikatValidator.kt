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
class SertifikatValidator(val ocspChecker: OCSPChecker, val ssnCache: SsnCache) {


    internal fun validateCertificate(x509Certificate: X509Certificate, dateInstant: Instant): SertifikatInfo {
        log.debug(x509Certificate.toString())
        try {
            x509Certificate.checkValidity(Date(dateInstant.toEpochMilli()))

            if (isSelfSigned(x509Certificate)) {
                throw SertifikatError(HttpStatus.BAD_REQUEST, SERTIFIKAT_SELF_SIGNED, sertifikatSelvsignert(x509Certificate))
            }
            if (isVirksomhetssertifikat(x509Certificate)) {
                log.info("Virksomhetssertifikat, sjekker crl")
                //TODO CRL sjekk
                sertifikatOK(x509Certificate)
            } else {
                val ssn = ssnCache.getSSN(x509Certificate)
                if (ssn == null) {
                    log.info("SSN finnes ikke i cache, sjekker OCSP")
                    val ocspResponse = ocspChecker.getOCSPStatus(x509Certificate)
                    log.info("Respons fra OCSP check: $ocspResponse")
                    ssnCache.updateSSNCacheValue(x509Certificate, ocspResponse.fnr!!)
                    if (ocspResponse.status == SertifikatStatus.REVOKERT) {
                        return ocspResponse
                    }
                }
                else {
                    log.info("SSN finnes i cache, sjekker CRL istedenfor")
                    return sertifikatOK(x509Certificate, ssn)
                }
            }

            return sertifikatOK(x509Certificate)
        } catch (e: CertificateExpiredException) {
            throw SertifikatError(HttpStatus.BAD_REQUEST, SERTIFIKAT_IKKE_GYLDIG_LENGER, sertifikatUtloept(x509Certificate), e)
        } catch (e: CertificateNotYetValidException) {
            throw SertifikatError(HttpStatus.BAD_REQUEST, SERTIFIKAT_IKKE_GYLDIG_ENDA, sertifikatIkkeGyldigEnda(x509Certificate), e)
        }
    }
}


