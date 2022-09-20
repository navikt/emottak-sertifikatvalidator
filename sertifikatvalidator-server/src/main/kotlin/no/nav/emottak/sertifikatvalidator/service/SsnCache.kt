package no.nav.emottak.sertifikatvalidator.service

import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.SertifikatError
import org.springframework.http.HttpStatus
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Service
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap

@Service
class SsnCache {

    private val ssnCache = ConcurrentHashMap<String,String>()

    fun getSSN(certificate: X509Certificate) = ssnCache[createSSNCacheKey(certificate)]

    fun updateSSNCacheValue(certificate: X509Certificate, ssn: String) {
        ssnCache[createSSNCacheKey(certificate)] = ssn
    }

    private fun createSSNCacheKey(certificate: X509Certificate): String {
        val serialnumber = certificate.serialNumber ?: throw SertifikatError(HttpStatus.BAD_REQUEST, "Missing serialnumber in certificate")
        val issuer = certificate.issuerX500Principal.name ?: throw SertifikatError(HttpStatus.BAD_REQUEST, "Missing issuer name in certificate")
        return "$issuer$serialnumber"
    }

    @Scheduled(cron = "\${schedule.cron.cache.ssn}")
    private fun clearCache() {
        log.info("Scheduled clearing of ssn cache. ${cacheCount()} items in cache before clearing.")
        ssnCache.clear()
        log.info("Scheduled clearing of ssn cache. ${cacheCount()} items in cache after clearing.")
    }

    internal fun cacheCount(): Int {
        val ssnCount = ssnCache.size
        return ssnCount
    }
}