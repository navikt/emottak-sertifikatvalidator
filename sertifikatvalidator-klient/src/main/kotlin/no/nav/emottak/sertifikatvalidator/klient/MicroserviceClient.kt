package no.nav.emottak.sertifikatvalidator.klient

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import no.nav.emottak.sertifikatvalidator.SERVICE_URL_DEV
import no.nav.emottak.sertifikatvalidator.SERVICE_URL_PROD
import no.nav.emottak.sertifikatvalidator.model.ServerStatus
import okhttp3.OkHttpClient
import okhttp3.Request
import org.slf4j.Logger
import org.slf4j.LoggerFactory

abstract class MicroserviceClient {

    private val clientVersion: String? = javaClass.`package`.implementationVersion
    protected val objectMapper = jacksonObjectMapper()
    protected var httpClient = OkHttpClient.Builder().build()

    abstract fun checkServerCompatibility(): ServerStatus

    protected fun createServerStatusResponse(status: Boolean): ServerStatus {
        val statusMessage = when (status){
            true -> "OK"
            false -> "NOK"
        }
        val beskrivelse = when (status) {
            true -> "Klient og server er kompatible!"
            false -> "Klient og server er ikke kompatible. Oppdater klient eller sjekk serverstatus"
        }
        return ServerStatus(
            status = statusMessage,
            beskrivelse = beskrivelse,
            kompatibel = status,
            version = clientVersion ?: "Unknown"
        )
    }

    protected fun createServerStatusErrorResponse(exception: Exception): ServerStatus {
        log.error("Server/klient i usync, eller server er nede.", exception)
        return ServerStatus(
            status = "Feil med tjenesten",
            beskrivelse = "Klient og ikke er kompatible. Kanskje tjenesten er nede? (${exception.message}",
            kompatibel = false,
            version = clientVersion ?: "Unknown"
        )
    }

    protected fun <T> postRequestToService(
        url: String,
        request: Request,
        responseClass: Class<T>
    ): T {
        try {
            log.debug("Kaller $url")
            val response = httpClient.newCall(request).execute()
            if (response.isSuccessful) {
                log.debug("Kall mot $url gjennomført")
            } else {
                log.warn("${response.code} feil ved kall til $url")
            }
            return objectMapper.readValue(response.body?.string(), responseClass)
        } catch (e: Exception) {
            log.error("Ukjent feil ved kall til $url", e)
            throw e
        }
    }
}

internal val log: Logger = LoggerFactory.getLogger(MicroserviceClient::class.java)

internal val serviceUrl = run {
    val environment = getEnvVar("NAIS_CLUSTER_NAME", "dev")
    if (environment.startsWith("prod", ignoreCase = true)) {
        SERVICE_URL_PROD
    } else {
        SERVICE_URL_DEV
    }
}

fun getEnvVar(varName: String, defaultValue: String? = null) =
    System.getProperty(varName, System.getenv(varName)) ?: defaultValue ?: throw RuntimeException("Missing required variable $varName")
