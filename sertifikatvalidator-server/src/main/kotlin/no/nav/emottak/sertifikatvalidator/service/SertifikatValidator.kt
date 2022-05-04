package no.nav.emottak.sertifikatvalidator.service

import no.nav.emottak.sertifikatvalidator.ALL_REVOCATION_CHECKS_DISABLED
import no.nav.emottak.sertifikatvalidator.CERTIFICATE_ISSUER_UNKNOWN
import no.nav.emottak.sertifikatvalidator.OCSP_VERIFICATION_UKJENT_FEIL
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_GYLDIG
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_GYLDIG_ENDA
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_GYLDIG_LENGER
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_SELF_SIGNED
import no.nav.emottak.sertifikatvalidator.UKJENT_FEIL
import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.SEIDVersion
import no.nav.emottak.sertifikatvalidator.model.SertifikatData
import no.nav.emottak.sertifikatvalidator.model.SertifikatError
import no.nav.emottak.sertifikatvalidator.model.SertifikatInfo
import no.nav.emottak.sertifikatvalidator.model.SertifikatStatus
import no.nav.emottak.sertifikatvalidator.util.KeyStoreHandler
import no.nav.emottak.sertifikatvalidator.util.getOrganizationNumber
import no.nav.emottak.sertifikatvalidator.util.getSEIDVersion
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
import java.security.cert.CertPathBuilder
import java.security.cert.CertPathBuilderException
import java.security.cert.CertStore
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.PKIXBuilderParameters
import java.security.cert.PKIXCertPathBuilderResult
import java.security.cert.TrustAnchor
import java.security.cert.X509CertSelector
import java.time.Instant
import java.util.Date


@Service
class SertifikatValidator(val ocspChecker: OCSPChecker, val crlChecker: CRLChecker, val ssnCache: SsnCache) {


    internal fun validateCertificate(sertifikatData: SertifikatData, dateInstant: Instant): SertifikatInfo {
        log.info("UUID ${sertifikatData.uuid} Serienummer ${sertifikatData.sertifikat.serialNumber}: sertifikatvalidering startet")
        log.info(sertifikatData.sertifikat.toString())
        try {
            sjekkOmSertifikatErSelvsignert(sertifikatData)
            sjekkSertifikatMotTrustedCa(sertifikatData)

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

    private fun sjekkSertifikatMotTrustedCa(sertifikatData: SertifikatData) {
        val trustedRootCerts = KeyStoreHandler.getTrustedRootCerts()
        val intermediateCerts = KeyStoreHandler.getIntermediateCerts()

        val selector = X509CertSelector()
        selector.certificate = sertifikatData.sertifikat
        val trustAnchors = trustedRootCerts.map {
            TrustAnchor(it, null)
        }.toSet()

        val pkixParams = PKIXBuilderParameters(trustAnchors, selector)
        pkixParams.isRevocationEnabled = false

        val intermediateCertStore = CertStore.getInstance("Collection", CollectionCertStoreParameters(intermediateCerts), "BC")
        pkixParams.addCertStore(intermediateCertStore)

        val builder = CertPathBuilder.getInstance("PKIX", "BC")
        try {
            builder.build(pkixParams) as PKIXCertPathBuilderResult
        } catch (e: CertPathBuilderException) {
            throw SertifikatError(HttpStatus.BAD_REQUEST, "${sertifikatData.uuid} $CERTIFICATE_ISSUER_UNKNOWN ${sertifikatData.sertifikat.issuerX500Principal.name}", sertifikatData, e)
        }
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

    private fun sjekkCRL(sertifikatData: SertifikatData, ssn: String?): SertifikatInfo {
        val sertifikat = sertifikatData.sertifikat
        try {
            val crlRevocationInfo =
                crlChecker.getCRLRevocationInfo(sertifikat.issuerX500Principal.name, sertifikat.serialNumber)
            if (crlRevocationInfo.revoked) {
                log.info("UUID ${sertifikatData.uuid} Sertifikat revokert (CRL)")
                return sertifikatRevokert(sertifikatData, crlRevocationInfo.revocationReason)
            }
            return sertifikatOK(sertifikatData, ssn)
        } catch (e: Exception) {
            val crlDistributionPoint = sertifikat.getExtensionValue(Extension.cRLDistributionPoints.toString())
            val crlDistributionPoints = CRLDistPoint.getInstance(JcaX509ExtensionUtils.parseExtensionValue(crlDistributionPoint))
            log.info("-------------------------------------------------")
            log.info("UUID ${sertifikatData.uuid}")
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
            log.info("UUID ${sertifikatData.uuid} Sertifikat revokert (OCSP)")
            return ocspResponse
        }
        return sertifikatOK(sertifikatData, fnr)
    }

    private fun sjekkVirksomhetssertifikat(sertifikatData: SertifikatData, sjekkCRL: Boolean, sjekkOCSP: Boolean): SertifikatInfo {
        val sertifikat = sertifikatData.sertifikat
        val seidVersion = getSEIDVersion(sertifikat)
        val orgnummer = getOrganizationNumber(sertifikat)
        log.info("UUID ${sertifikatData.uuid} er et virksomhetssertifikat, sjekkCRL: $sjekkCRL, sjekkOCSP: $sjekkOCSP")
        log.info("UUID ${sertifikatData.uuid} er et $seidVersion sertifikat med orgnummer $orgnummer")
        if (seidVersion == SEIDVersion.SEID20 && orgnummer.isNullOrEmpty()) {
            log.warn("UUID ${sertifikatData.uuid} er et $seidVersion sertifikat og orgnummeruthenting feilet!")
        }
        return try {
            if(sjekkCRL)
                sjekkCRL(sertifikatData, null)
            else
                sjekkOCSP(sertifikatData)
        } catch (e: Exception) {
            log.warn("UUID ${sertifikatData.uuid} Sjekk av CRL feilet, sjekker OCSP", e)
            if (sjekkOCSP) sjekkOCSP(sertifikatData) else throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, UKJENT_FEIL, sertifikatUkjentFeil(sertifikatData))
        }
    }

    private fun sjekkPersonligSertifikat(sertifikatData: SertifikatData, sjekkCRL: Boolean, sjekkOCSP: Boolean): SertifikatInfo {
        val sertifikat = sertifikatData.sertifikat
        log.info("UUID ${sertifikatData.uuid} er et personlig sertifikat, sjekkCRL: $sjekkCRL, sjekkOCSP: $sjekkOCSP")
        log.info("UUID ${sertifikatData.uuid} er et ${getSEIDVersion(sertifikat)} sertifikat")
        val ssn = ssnCache.getSSN(sertifikat)
        if (ssn == null || !sjekkCRL) {
            log.info("UUID ${sertifikatData.uuid} SSN finnes ikke i cache, sjekker OCSP")
            return try {
                sjekkOCSP(sertifikatData)
            }
            catch (e: Exception) {
                if(sjekkCRL) {
                    log.warn("UUID ${sertifikatData.uuid} OCSP sjekk feilet, sjekker CRL", e)
                    sjekkCRL(sertifikatData, null)
                }
                else {
                    log.warn("UUID ${sertifikatData.uuid} OCSP sjekk feilet, men skipper backup CRL-sjekk fordi sjekkCRL = $sjekkCRL")
                    throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, OCSP_VERIFICATION_UKJENT_FEIL, sertifikatOCSPValideringFeilet(sertifikatData))
                }
            }
        } else {
            log.info("UUID ${sertifikatData.uuid} SSN finnes i cache, sjekkCRL = $sjekkCRL, sjekkOCSP = $sjekkOCSP")
            return if (sjekkCRL) {
                sjekkCRL(sertifikatData, ssn)
            }
            else {
                sjekkOCSP(sertifikatData)
            }
        }
    }
}


