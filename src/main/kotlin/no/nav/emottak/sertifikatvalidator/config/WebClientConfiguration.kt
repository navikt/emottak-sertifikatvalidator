package no.nav.emottak.sertifikatvalidator.config

import org.eclipse.jetty.client.HttpClient
import org.eclipse.jetty.client.HttpProxy
import org.eclipse.jetty.client.ProxyConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.client.reactive.ClientHttpConnector
import org.springframework.http.client.reactive.JettyClientHttpConnector
import org.springframework.web.reactive.function.client.WebClient


@Configuration
class WebClientConfiguration() {

    private var proxyHost: String? = System.getProperty("http.proxyHost")
    private var proxyPort: String? = System.getProperty("http.proxyPort")
    private var nonProxyHosts: String? = System.getProperty("http.nonProxyHosts")

    @Bean
    fun webClient(): WebClient {

        val httpClient = HttpClient()
        if (!proxyHost.isNullOrBlank() && !proxyPort.isNullOrBlank() && !nonProxyHosts.isNullOrBlank()) {
            val proxyConfig: ProxyConfiguration = httpClient.proxyConfiguration
            val proxy = HttpProxy(proxyHost, proxyPort!!.toInt())
            nonProxyHosts!!.split("|").forEach { nonProxyHost ->
                proxy.excludedAddresses.add(nonProxyHost)
            }
            proxyConfig.proxies.add(proxy)
        }

        val connector: ClientHttpConnector = JettyClientHttpConnector(httpClient)
        //val connector = ReactorClientHttpConnector(httpClient)

        return WebClient.builder()
            .codecs { configurer -> configurer.defaultCodecs().maxInMemorySize(16 * 1024 * 1024) }
            .clientConnector(connector)
            .build()
    }

}