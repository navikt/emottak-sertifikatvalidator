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
    protected val objectMapper = jacksonObjectMapper()
    protected var httpClient = OkHttpClient.Builder().build()
    protected val accessToken = AccessTokenHolder().token.value

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

private val clientId = getEnvVar("AZURE_APP_CLIENT_ID")
private val clientSecret = getEnvVar("AZURE_APP_CLIENT_SECRET")
private val clusterName = "dev-fss"
private val namespace = "team-emottak"
private val applicationName = "emottak-kryptering"
private val scope = "api://$clusterName.$namespace.$applicationName/.default"
private val tenant = getEnvVar("AZURE_APP_TENANT_ID")
private val tokenEndpoint = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token"

private class AccessTokenHolder {

    private lateinit var accessToken: AccessToken

    init {
        refreshAccessToken()
    }

    var token = run {
        if (accessTokenExpired()) {
            refreshAccessToken()
            accessToken
        } else {
            accessToken
        }
    }

    private fun refreshAccessToken() {
        log.info("AccessToken refreshing")
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
            this.accessToken = accessToken
            log.info("AccessToken refreshed")
        } catch (e: Exception) {
            log.error("Failed to get access token with error ${e.localizedMessage}. Check debug logging if problem persists.")
            log.debug("Failed to get access token from $tokenEndpoint with client $clientId")
            log.debug("Failed to get access token", e)
        }
    }

    private fun accessTokenExpired(): Boolean {
        val jwt = SignedJWT.parse(accessToken.value)
        val expirationTime = jwt.jwtClaimsSet.expirationTime
        log.debug("AccessToken expires at $expirationTime")
        if (expirationTime.before(Date(Instant.now().epochSecond + 900))) {
            log.debug("AccessToken expires soon, should get a new one")
            return true
        } else {
            return false
        }
    }

}
