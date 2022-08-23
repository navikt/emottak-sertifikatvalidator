package no.nav.emottak.sertifikatvalidator.klient

import com.fasterxml.jackson.databind.exc.MismatchedInputException
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.AuthorizationGrant
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.TokenRequest
import com.nimbusds.oauth2.sdk.TokenResponse
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic
import com.nimbusds.oauth2.sdk.auth.Secret
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.token.AccessToken
import no.nav.emottak.sertifikatvalidator.BACKEND_APPLICATION_NAME
import no.nav.emottak.sertifikatvalidator.BACKEND_CLUSTER_DEV
import no.nav.emottak.sertifikatvalidator.BACKEND_CLUSTER_PROD
import no.nav.emottak.sertifikatvalidator.BACKEND_NAMESPACE
import no.nav.emottak.sertifikatvalidator.SERVICE_URL_DEV
import no.nav.emottak.sertifikatvalidator.SERVICE_URL_PROD
import no.nav.emottak.sertifikatvalidator.model.ServerStatus
import okhttp3.OkHttpClient
import okhttp3.Request
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.net.URI
import java.time.Instant
import java.util.Date

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
    if (isProduction()) {
        log.debug("Production environment, using $SERVICE_URL_PROD")
        SERVICE_URL_PROD
    } else {
        log.debug("Development environment, using $SERVICE_URL_DEV")
        SERVICE_URL_DEV
    }
}

private val cluster = run {
    if (isProduction()) {
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

fun getEnvVar(varName: String, defaultValue: String? = null) =
    System.getProperty(varName, System.getenv(varName)) ?: defaultValue ?: throw RuntimeException("Missing required variable $varName")

private val clientId = getEnvVar("AZURE_APP_CLIENT_ID")
private val clientSecret = getEnvVar("AZURE_APP_CLIENT_SECRET")
private val tenant = getEnvVar("AZURE_APP_TENANT_ID")
private val tokenEndpoint = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token"
private val scope = "api://$cluster.$BACKEND_NAMESPACE.$BACKEND_APPLICATION_NAME/.default"

private class AccessTokenHolder {

    private var accessToken: AccessToken? = null

    fun getToken(): AccessToken {
        if (accessToken == null) {
            accessToken = refreshAccessToken()
        }
        else if (accessTokenExpired()) {
            accessToken = refreshAccessToken()
        }
        return accessToken!!
    }

    private fun refreshAccessToken(attempt: Int = 1): AccessToken {
        log.info("AccessToken refreshing")
        val retries = 3
        val waitTime = 5
        val clientGrant: AuthorizationGrant = ClientCredentialsGrant()
        val clientID = ClientID(clientId)
        val clientSecret = Secret(clientSecret)
        val clientAuth: ClientAuthentication = ClientSecretBasic(clientID, clientSecret)
        val scope = Scope(scope)
        val tokenEndpointURI = URI(tokenEndpoint)
        val request = TokenRequest(tokenEndpointURI, clientAuth, clientGrant, scope)
        try {
            val response = TokenResponse.parse(request.toHTTPRequest().send())
            if (!response.indicatesSuccess()) {
                val errorResponse = response.toErrorResponse()
                log.warn("statusCode fra token server: ${response.toHTTPResponse().statusCode}")
                log.warn("content fra token server: ${response.toHTTPResponse().content}")
                throw RuntimeException(errorResponse.errorObject.description)
            }
            val successResponse = response.toSuccessResponse()
            val accessToken = successResponse.tokens.accessToken
            log.info("AccessToken refreshed")
            return accessToken
        } catch (e: Exception) {
            log.error("Failed to refresh access token with error ${e.localizedMessage}. Check debug logging if problem persists.")
            log.debug("Failed to refresh access token from $tokenEndpoint with client $clientId", e)
            if (attempt <= retries) {
                Thread.sleep((waitTime * 1000).toLong())
                return refreshAccessToken(attempt+1)
            }
            else throw RuntimeException("Refresh AccessToken failed after $attempt tries... try again later")
        }
    }

    private fun accessTokenExpired(): Boolean {
        val token = accessToken ?: return true
        val jwt = SignedJWT.parse(token.value)
        val expirationTime = jwt.jwtClaimsSet.expirationTime
        val certificateTimeThreshold = Date.from(Instant.now().plusSeconds(900))
        log.debug("AccessToken expires at $expirationTime, update if time before $certificateTimeThreshold")
        return if (expirationTime.before(certificateTimeThreshold)) {
            log.info("AccessToken expires soon, should get a new one")
            true
        } else {
            false
        }
    }

}
