package no.nav.emottak.sertifikatvalidator.klient

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
import no.nav.emottak.sertifikatvalidator.BACKEND_NAMESPACE
import java.net.URI
import java.time.Instant
import java.util.Date

internal class AccessTokenHolder {

    private val clientId = getEnvVar("AZURE_APP_CLIENT_ID")
    private val clientSecret = getEnvVar("AZURE_APP_CLIENT_SECRET")
    private val tenant = getEnvVar("AZURE_APP_TENANT_ID")
    private val tokenEndpoint = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token"
    private val scope = "api://$backendCluster.$BACKEND_NAMESPACE.$BACKEND_APPLICATION_NAME/.default"
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
