package no.nav.emottak.sertifikatvalidator.config

import no.nav.emottak.sertifikatvalidator.log
import org.eclipse.jetty.client.HttpClient
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.client.reactive.JettyClientHttpConnector
import org.springframework.web.reactive.function.client.WebClient


@Configuration
class WebClientConfiguration() {

    private var proxyHost: String? = System.getProperty("http.proxyHost")
    private var proxyPort: String? = System.getProperty("http.proxyPort")
    private var nonProxyHosts: String? = System.getProperty("http.nonProxyHosts")

    @Bean
    fun webClient(): WebClient {
        val httpClient = HttpClient()//.proxyWithSystemProperties()
        configureProxy(httpClient)
        //val connector = ReactorClientHttpConnector(httpClient)
        val connector = JettyClientHttpConnector(httpClient)

        return WebClient.builder()
            .codecs { configurer -> configurer.defaultCodecs().maxInMemorySize(16 * 1024 * 1024) }
            .clientConnector(connector)
            .build()
    }

    private fun configureProxy(httpClient: HttpClient) {
        if (!proxyHost.isNullOrBlank() && !proxyPort.isNullOrBlank()) {
            log.info("Setting proxy settings $proxyHost:$proxyPort")
//            httpClient.proxy { proxy: ProxyProvider.TypeSpec ->
//                proxy.type(ProxyProvider.Proxy.HTTP)
//                    .host(proxyHost!!)
//                    .port(proxyPort!!.toInt()).build()
//                    //.nonProxyHosts(nonProxyHosts!!.replace("*", ".*?"))
//                    //.nonProxyHostsPredicate(NonProxyHostsPredicate.fromWildcardedPattern(nonProxyHosts!!))
//            }.wiretap(true)
        }
    }

}