package no.nav.emottak.sertifikatvalidator.config

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtDecoders
import org.springframework.security.oauth2.jwt.JwtValidators
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.web.SecurityFilterChain

@EnableWebSecurity
@Configuration
class SecurityConfiguration {

    @Autowired
    private lateinit var oAuth2ResourceServerProperties: OAuth2ResourceServerProperties

    @Value("\${spring.security.oauth2.resourceserver.jwt.accepted-audience}")
    private lateinit var acceptedAudience: List<String>

    @Bean
    @Throws(Exception::class)
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http.sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .csrf()
            .disable()
            .authorizeRequests()
            .antMatchers(
                "/internal/health/liveness",
                "/internal/health/readiness",
                "/internal/prometheus",
                "/internal/swagger",
                "/internal/swagger-ui/*",
                "/internal/api-docs/swagger-config",
                "/internal/api-docs",
                "/internal/status/crl",
                "/internal/status/crl/update",
                "/internal/status/fnr/cache/count",
                "/internal/status/server/klient")
            .permitAll()
            .anyRequest()
            .permitAll()
//            .fullyAuthenticated()
//            .and()
//            .oauth2ResourceServer()
//            .jwt()
//            .decoder(jwtDecoder())
        return http.build()
    }

    @Bean
    fun jwtDecoder(): JwtDecoder {
        val jwtDecoder: NimbusJwtDecoder = JwtDecoders.fromOidcIssuerLocation(
            oAuth2ResourceServerProperties.jwt.issuerUri
        ) as NimbusJwtDecoder
        jwtDecoder.setJwtValidator(oAuth2TokenValidator())
        return jwtDecoder
    }

    @Bean
    fun oAuth2TokenValidator(): OAuth2TokenValidator<Jwt> {
        val issuerValidator: OAuth2TokenValidator<Jwt> = JwtValidators.createDefaultWithIssuer(
            oAuth2ResourceServerProperties.jwt.issuerUri
        )
        val audienceValidator: OAuth2TokenValidator<Jwt> =
            OAuth2TokenValidator<Jwt> { token ->
                if (token.audience.stream().anyMatch(acceptedAudience::contains)) {
                    OAuth2TokenValidatorResult.success()
                } else {
                    OAuth2TokenValidatorResult.failure(
                        OAuth2Error(
                            "invalid_token",
                            "None of required audience values $acceptedAudience found in token",
                            null
                        )
                    )
                }
            }
        return DelegatingOAuth2TokenValidator(issuerValidator, audienceValidator)
    }
}