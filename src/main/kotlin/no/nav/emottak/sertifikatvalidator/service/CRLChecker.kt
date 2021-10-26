package no.nav.emottak.sertifikatvalidator.service

import no.nav.emottak.sertifikatvalidator.CERTIFICATE_ISSUER_UNKNOWN
import no.nav.emottak.sertifikatvalidator.FAILED_TO_CREATE_CRL
import no.nav.emottak.sertifikatvalidator.REVOCATION_REASON_UNKNOWN
import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.CRLHolder
import no.nav.emottak.sertifikatvalidator.model.CRLRevocationInfo
import no.nav.emottak.sertifikatvalidator.model.SertifikatError
import no.nav.emottak.sertifikatvalidator.util.getEnvVar
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.springframework.http.HttpStatus
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import reactor.netty.http.client.HttpClient
import java.io.InputStream
import java.math.BigInteger
import java.security.Provider
import java.security.cert.CRLException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.security.cert.X509CRLEntry
import java.util.*


@Service
class CRLChecker {

    private var crlFiles: HashMap<X500Name, CRLHolder> = HashMap(2)
    private val buypassDN: X500Name = X500Name(getEnvVar("BUYPASS_DN", "CN=Buypass Class 3 Test4 CA 3,O=Buypass AS-983163327,C=NO"))
    //private val buypassDN: String = getEnvVar("BUYPASS_DN", "CN=Buypass Class 3 Test4 CA 1,O=Buypass,C=NO")
    private val buypassCRL: String = getEnvVar("BUYPASS_CRL", "http://crl.test4.buypass.no/crl/BPClass3T4CA3.crl")
    private val commfidesDN: X500Name = X500Name(getEnvVar("COMMFIDES_DN", "C=NO, O=Commfides Norge AS - 988 312 495, OU=CPN Enterprise-Norwegian SHA256 CA- TEST, OU=Commfides Trust Environment(C) 2014 Commfides Norge AS - TEST, CN=Commfides CPN Enterprise-Norwegian SHA256 CA - TEST"))
    private val commfidesCRL: String = getEnvVar("COMMFIDES_CRL", "http://crl1.test.commfides.com/CommfidesEnterprise-SHA256.crl")

    private val provider: Provider = BouncyCastleProvider()

    init {
        createCrls()
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

    @Scheduled(cron = "\${schedule.cron.crl}")
    private fun updateCRLsPeriodically() {
        log.info("Oppdaterer CRL-filer")
        crlFiles.forEach { crlEntry ->
            if (isExpired(crlEntry.value.crl)) {
                log.info("${crlEntry.key}: CRL er utløpt, henter oppdatering")
                createCrl(crlEntry.value)
            }
        }
    }

    private fun getRevokedCertificate(issuer: String, serialNumber: BigInteger): X509CRLEntry? {
        return getCrl(issuer).getRevokedCertificate(serialNumber)
    }

    fun getCrl(issuer: String): X509CRL {
        val issuerX500Name = X500Name(issuer)
        val crlHolder = crlFiles[issuerX500Name] ?: throw SertifikatError(HttpStatus.BAD_REQUEST, "Ukjent sertifikatutsteder $issuer, kunne ikke sjekke CRL")
        val crlFile: X509CRL = crlHolder.crl
        return if (isExpired(crlFile)) {
            createCrl(crlHolder)
        }
        else {
            crlFile
        }
    }

    private fun isExpired(crlFile: X509CRL): Boolean {
        return crlFile.nextUpdate.before(Date())
    }

    private fun createCrl(crlHolder: CRLHolder): X509CRL {
        try {
            crlHolder.crl = createCRL(getCrlFileFromUrl(crlHolder.crlUrl))
            log.info("${crlHolder.crlUrl}: CRL oppdatert")
        } catch (e: Exception) {
            throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, "${crlHolder.crlUrl}: Kunne ikke oppdatere CRL", e)
        }
        return crlHolder.crl
    }

    private fun getCrlFileFromUrl(crlUrl: String): InputStream {
        log.info("Henter URL $crlUrl")
        val httpClient = HttpClient.create().proxyWithSystemProperties()
//        if (!proxyHost.isNullOrBlank() && !proxyPort.isNullOrBlank()) {
//            log.info("Setting proxy settings $proxyHost:$proxyPort")
//            httpClient.proxy { proxy: TypeSpec ->
//                proxy.type(ProxyProvider.Proxy.HTTP)
//                    .host(proxyHost!!)
//                    .port(proxyPort!!.toInt())
//                    //.nonProxyHosts(nonProxyHosts!!)
//                    //.build()
//            }
//        }

        val connector = ReactorClientHttpConnector(httpClient)
        val response = WebClient.builder().clientConnector(connector)
            .baseUrl(crlUrl)
            .codecs { configurer ->
                configurer.defaultCodecs().maxInMemorySize(16 * 1024 * 1024)
            }
            .build()
            .get()
            //.accept(MediaType("application", "pkix-crl"), MediaType("application", "x-pkcs7-crl"))
            .retrieve()
            .bodyToMono(ByteArray::class.java)
            //.retryWhen(Retry.backoff(3, Duration.ofSeconds(5)))
        return response.block()?.inputStream() ?: throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, "$crlUrl: Feil ved henting av CRL fra URL")
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

    private fun createCrls() {
        log.info("Henter CRL info")
        updateCrlForDN(buypassDN, buypassCRL)
        updateCrlForDN(commfidesDN, commfidesCRL)
        log.info("CRL oppdatert med ${crlFiles.size} lister")
    }

    private fun updateCrlForDN(dn: X500Name, crlUrl: String) {
        try {
            log.info("Henter CRL: ${dn}, ${crlUrl}")
            val crlHolder = CRLHolder(dn, crlUrl, createCRL(getCrlFileFromUrl(crlUrl)))
            log.info("CRL hentet: ${dn}, ${crlUrl}, ${crlHolder.updatedDate}")
            crlFiles[dn] = crlHolder
        } catch (e: Exception) {
            log.error("Henting av CRL for $dn på $crlUrl feilet", e)
        }
    }
}