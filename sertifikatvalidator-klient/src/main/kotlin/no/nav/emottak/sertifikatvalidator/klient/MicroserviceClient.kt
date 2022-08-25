package no.nav.emottak.sertifikatvalidator.klient

import com.fasterxml.jackson.databind.exc.MismatchedInputException
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import no.nav.emottak.sertifikatvalidator.BACKEND_CLUSTER_DEV
import no.nav.emottak.sertifikatvalidator.BACKEND_CLUSTER_PROD
import no.nav.emottak.sertifikatvalidator.BACKEND_NAMESPACE
import no.nav.emottak.sertifikatvalidator.SERVICE_URL_DEV
import no.nav.emottak.sertifikatvalidator.SERVICE_URL_LOCAL
import no.nav.emottak.sertifikatvalidator.SERVICE_URL_PROD
import no.nav.emottak.sertifikatvalidator.model.ServerStatus
import okhttp3.OkHttpClient
import okhttp3.Request
import org.slf4j.Logger
import org.slf4j.LoggerFactory

abstract class MicroserviceClient {

    private val clientVersion: String? = javaClass.`package`.implementationVersion
    private val objectMapper = jacksonObjectMapper()
    private var httpClient = OkHttpClient.Builder().build()
    private val accessTokenHolder = AccessTokenHolder()
    var retryDelay = 3000L
    var retries = 3

    protected fun getAccessToken(): String {
        return accessTokenHolder.getToken().value
    }

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
        responseClass: Class<T>,
        attempt: Int,
        messageId: String
    ): T {
        try {
            log.debug("Validerer sertifikat mot $url mottakId=$messageId")
            val response = httpClient.newCall(request).execute()
            if (response.isSuccessful) {
                log.info("Sertifikat OK mottakId=$messageId")
            } else if (response.code == 400 || response.code == 422) {
                log.warn("Sertifikatvalidering svarte med klienterror statusCode=${response.code}), sjekk input mottakId=$messageId")
            } else {
                log.warn("${response.code} feil ved kall til $url mottakId=$messageId")
                if (attempt < retries) {
                    Thread.sleep(retryDelay)
                    log.warn("Tidligere request feilet, starter forsøk $attempt mottakId=$messageId statusCode=${response.code}")
                    return postRequestToService(url, request, responseClass, attempt+1, messageId)
                }
                else {
                    log.warn("Request feilet etter $retries forsøk mottakId=$messageId statusCode=${response.code}")
                    throw RuntimeException("Autentisering feilet mot sertifikatvalidering, sannsynligvis feil med access token mottakId=$messageId")
                }
            }
            return objectMapper.readValue(response.body?.string(), responseClass)
        } catch (e: MismatchedInputException) {
            log.warn("Respons fra sertifikatvalidering er ikke gyldig: ${e.localizedMessage} mottakId=$messageId")
            log.debug("Respons fra sertifikatvalidering ($url) er ikke gyldig mottakId=$messageId", e)
            throw e
        } catch (e: Exception) {
            log.warn("Ukjent feil fra sertifikatvalidering: ${e.localizedMessage} mottakId=$messageId")
            log.debug("Feil ved kall til $url mottakId=$messageId", e)
            throw e
        }
    }
}

internal val log: Logger = LoggerFactory.getLogger(MicroserviceClient::class.java)

internal val serviceUrl = run {
    if (isSameClusterAndNamespace()) {
        log.debug("Running client in same cluster and namespace as server (${backendCluster()}, $BACKEND_NAMESPACE), using $SERVICE_URL_LOCAL")
        SERVICE_URL_LOCAL
    }
    else if (isProduction()) {
        log.debug("Production environment, using $SERVICE_URL_PROD")
        SERVICE_URL_PROD
    } else {
        log.debug("Development environment, using $SERVICE_URL_DEV")
        SERVICE_URL_DEV
    }
}

internal fun backendCluster(): String {
    return if (isProduction()) {
        log.debug("Production environment, using $BACKEND_CLUSTER_PROD")
        BACKEND_CLUSTER_PROD
    } else {
        log.debug("Development environment, using $BACKEND_CLUSTER_DEV")
        BACKEND_CLUSTER_DEV
    }
}

internal fun isProduction(): Boolean {
    val environment = getEnvVar("NAIS_CLUSTER_NAME", "dev")
    log.debug("Environment: $environment (isProduction = ${environment.startsWith("prod", ignoreCase = true)})")
    return environment.startsWith("prod", ignoreCase = true)
}

internal fun isSameClusterAndNamespace(): Boolean {
    val runningEnvironment = getEnvVar("NAIS_CLUSTER_NAME", "dev")
    val namespace = getEnvVar("NAIS_NAMESPACE", "")
    val backendCluster = backendCluster()
    val isSameCluster = runningEnvironment.equals(backendCluster, ignoreCase = true)
    val isSameNamespace = namespace.equals(BACKEND_NAMESPACE, ignoreCase = true)
    log.debug("Environment: $runningEnvironment ($backendCluster) Namespace: $namespace ($BACKEND_NAMESPACE) (isSameCluster = $isSameCluster, isSameNamespace = $isSameNamespace)")
    return isSameCluster && isSameNamespace
}

fun getEnvVar(varName: String, defaultValue: String? = null) =
    System.getProperty(varName, System.getenv(varName)) ?: defaultValue ?: throw RuntimeException("Missing required variable $varName")

