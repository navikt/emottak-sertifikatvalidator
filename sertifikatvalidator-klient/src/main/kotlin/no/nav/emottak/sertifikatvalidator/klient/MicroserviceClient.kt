package no.nav.emottak.sertifikatvalidator.klient

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
import no.nav.emottak.sertifikatvalidator.BACKEND_CLUSTER_NAME
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
    private val accessTokenHolder = AccessTokenHolder();

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
        responseClass: Class<T>
    ): T {
        try {
            log.info("Validerer sertifikat...")
            log.debug("Validerer sertifikat mot $url")
            val response = httpClient.newCall(request).execute()
            if (response.isSuccessful) {
                log.info("Sertifikat OK")
                log.debug("Sertifikatvalidering gjennomført, sertifikat OK")
            } else if (response.code == 401) {
                log.warn("Autentisering feilet mot sertifikatvalidering, sannsynligvis feil med access token")
                throw RuntimeException("Autentisering feilet mot sertifikatvalidering, sannsynligvis feil med access token")
            } else {
                log.warn("Sertifikat ikke OK, feilkode ${response.code}")
                log.debug("Feilkode ${response.code} fra $url")
            }
            return objectMapper.readValue(response.body?.string(), responseClass)
        } catch (e: Exception) {
            log.debug("Feil ved kall til $url", e)
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

private val clientId = getEnvVar("AZURE_APP_CLIENT_ID")
private val clientSecret = getEnvVar("AZURE_APP_CLIENT_SECRET")
private val tenant = getEnvVar("AZURE_APP_TENANT_ID")
private val tokenEndpoint = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token"
private const val scope = "api://$BACKEND_CLUSTER_NAME.$BACKEND_NAMESPACE.$BACKEND_APPLICATION_NAME/.default"

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
        log.info("AccessToken expires at $expirationTime, update if time before $certificateTimeThreshold")
        return if (expirationTime.before(certificateTimeThreshold)) {
            log.info("AccessToken expires soon, should get a new one")
            true
        } else {
            false
        }
    }

}
