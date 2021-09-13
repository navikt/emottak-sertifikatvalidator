package no.nav.emottak.sertifikatvalidator.service

import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_GYLDIG_ENDA
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_GYLDIG_LENGER
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_SELF_SIGNED
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_VALIDERING_OK
import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.SertifikatInfo
import no.nav.emottak.sertifikatvalidator.model.SertifikatStatus
import no.nav.emottak.sertifikatvalidator.util.OCSPChecker
import no.nav.emottak.sertifikatvalidator.util.createSertifikatInfoFromX509Certificate
import no.nav.emottak.sertifikatvalidator.util.isSelfSigned
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Date


internal fun validateCertificate(x509Certificate: X509Certificate, dateInstant: Instant): SertifikatInfo {
    log.debug(x509Certificate.toString())
    try {
        x509Certificate.checkValidity(Date(dateInstant.toEpochMilli()))

        if (isSelfSigned(x509Certificate)) {
            log.warn(SERTIFIKAT_SELF_SIGNED)
            return createSertifikatInfoFromX509Certificate(x509Certificate, SertifikatStatus.FEIL_MED_SERTIFIKAT, SERTIFIKAT_SELF_SIGNED)
        }
        //TODO
        OCSPChecker.getOCSPStatus(x509Certificate)
//        if (isRevoked(x509Certificate, dateInstant)) {
//            log.warn(SERTIFIKAT_REVOKERT)
//            return createSertifikatInfoFromX509Certificate(x509Certificate, SertifikatStatus.REVOKERT, SERTIFIKAT_REVOKERT)
//        }

        return createSertifikatInfoFromX509Certificate(x509Certificate, SertifikatStatus.OK, SERTIFIKAT_VALIDERING_OK)
    }
    catch (e: CertificateExpiredException) {
        log.warn(SERTIFIKAT_IKKE_GYLDIG_LENGER, e)
        return createSertifikatInfoFromX509Certificate(x509Certificate, SertifikatStatus.UTGAATT, SERTIFIKAT_IKKE_GYLDIG_LENGER)
    }
    catch (e: CertificateNotYetValidException) {
        log.warn(SERTIFIKAT_IKKE_GYLDIG_ENDA, e)
        return createSertifikatInfoFromX509Certificate(x509Certificate, SertifikatStatus.UTGAATT, SERTIFIKAT_IKKE_GYLDIG_ENDA)
    }
}


