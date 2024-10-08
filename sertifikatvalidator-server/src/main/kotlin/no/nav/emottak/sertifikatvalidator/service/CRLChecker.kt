package no.nav.emottak.sertifikatvalidator.service

import no.nav.emottak.sertifikatvalidator.CERTIFICATE_ISSUER_UNKNOWN
import no.nav.emottak.sertifikatvalidator.FAILED_TO_CREATE_CRL
import no.nav.emottak.sertifikatvalidator.REVOCATION_REASON_UNKNOWN
import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.CAHolder
import no.nav.emottak.sertifikatvalidator.model.CRLRevocationInfo
import no.nav.emottak.sertifikatvalidator.model.CertificateAuthorities
import no.nav.emottak.sertifikatvalidator.model.SertifikatError
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.context.event.ApplicationReadyEvent
import org.springframework.context.event.EventListener
import org.springframework.http.HttpStatus
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component
import org.springframework.web.client.RestTemplate
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.math.BigInteger
import java.security.Provider
import java.security.cert.CRLException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.security.cert.X509CRLEntry
import java.time.LocalDateTime
import java.util.Date


@Component
class CRLChecker(val webClient: RestTemplate) {

    @Autowired
    internal lateinit var certificateAuthorities: CertificateAuthorities
    private var crlFiles: HashMap<X500Name, CAHolder> = HashMap()
    private val provider: Provider = BouncyCastleProvider()

    @EventListener(ApplicationReadyEvent::class)
    fun updateCRLs() {
        updateCRLsPeriodically()
    }

    fun getCRLRevocationInfo(issuer: String, serialNumber: BigInteger): CRLRevocationInfo {
        return getRevokedCertificate(issuer = issuer, serialNumber = serialNumber)?.let { CRLRevocationInfo(
            serialNumber = serialNumber,
            revoked = true,
            revocationDate = it.revocationDate,
            revocationReason = it.revocationReason?.name ?: REVOCATION_REASON_UNKNOWN,
            sertificateIssuer = it.certificateIssuer?.name ?: CERTIFICATE_ISSUER_UNKNOWN
        ) } ?: CRLRevocationInfo(serialNumber = serialNumber, revoked = false, revocationReason = "Ikke revokert")
    }

    @Scheduled(cron = "\${schedule.cron.cache.crl}")
    private fun updateCRLsPeriodically() {
        log.info("Periodisk oppdatering av alle CRLer startet...")
        val crlUpdateStatus = StringBuilder()
        crlUpdateStatus
            .append("\n")
            .append("----------------------------------------\n")
            .append("Periodisk oppdatering av alle CRLer: ${certificateAuthorities.caList.size} CRLer konfigurert\n")
        var updateCounter = 0
        certificateAuthorities.caList.forEach { crl ->
            val x500Name = X500Name(crl.dn)
            crlUpdateStatus.append("${crl.name}\n")
            crlUpdateStatus.append("...henter oppdatert CRL fra ${crl.crlUrl}\n")
            try {
                updateCRL(crl)
                updateCounter++
                crlFiles[x500Name] = crl
                crlUpdateStatus.append("...oppdatert CRL fra ${crl.crlUrl}\n" )
                crlUpdateStatus.append("...oppdatert CRL er fra ${crl.crl?.thisUpdate}\n" )
            } catch (e: Exception) {
                crlUpdateStatus.append("...OBS! oppdatering av CRL feilet fra ${crl.crlUrl}\n")
                log.warn("Oppdatering av CRL feilet fra ${crl.crlUrl}", e)
            }
        }
        crlUpdateStatus.append("Periodisk oppdatering ferdig: $updateCounter/${certificateAuthorities.caList.size} CRLer oppdatert\n")
        crlUpdateStatus.append("----------------------------------------")
        log.info(crlUpdateStatus.toString())
    }

    private fun getRevokedCertificate(issuer: String, serialNumber: BigInteger): X509CRLEntry? {
        return getCrl(issuer).getRevokedCertificate(serialNumber)
    }

    fun getCrl(issuer: String): X509CRL {
        val issuerX500Name = X500Name(issuer)
        val crlHolder = crlFiles[issuerX500Name] ?: throw SertifikatError(HttpStatus.BAD_REQUEST, "Ukjent sertifikatutsteder $issuer, kunne ikke sjekke CRL")
        return if (isCRLNullOrExpired(crlHolder)) {
            updateCRL(crlHolder)
        }
        else {
            crlHolder.crl ?: updateCRL(crlHolder)
        }
    }

    private fun isCRLNullOrExpired(CAHolder: CAHolder): Boolean {
        val crl = CAHolder.crl
        if (crl == null) {
            log.info("${CAHolder.crlUrl}: CRL eksisterer ikke, hent ny")
            return true
        }
        else if (crl.nextUpdate.before(Date())) {
            log.info("${CAHolder.crlUrl}: CRL er utløpt, hent oppdatering")
            return true
        }
        return false
    }

    private fun updateCRL(CAHolder: CAHolder): X509CRL {
        try {
            val crl = createCRL(getCrlFileFromUrl(CAHolder.crlUrl))
            CAHolder.crl = crl
            CAHolder.cachedDate = LocalDateTime.now()
            return crl
        } catch (e: Exception) {
            throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, "${CAHolder.crlUrl}: Kunne ikke oppdatere CRL", e)
        }
    }

    private fun getCrlFileFromUrl(crlUrl: String): InputStream {
        val response = webClient.getForEntity(crlUrl, ByteArray::class.java)
        return ByteArrayInputStream(response.body ?: throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, "$crlUrl: Feil ved henting av CRL fra URL"))
    }

    private fun createCRL(input: InputStream?): X509CRL {
        return try {
            val factory = CertificateFactory.getInstance("X.509", provider)
            factory.generateCRL(input) as X509CRL
        } catch (e: CRLException) {
            throw RuntimeException(FAILED_TO_CREATE_CRL + ", " + e.message, e)
        } catch (e: CertificateException) {
            throw RuntimeException(FAILED_TO_CREATE_CRL + ", " + e.message, e)
        }
    }

}