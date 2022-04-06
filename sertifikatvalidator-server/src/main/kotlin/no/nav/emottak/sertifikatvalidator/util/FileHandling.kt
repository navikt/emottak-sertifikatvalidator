package no.nav.emottak.sertifikatvalidator.util

import no.nav.emottak.sertifikatvalidator.FEIL_BASE64_X509CERTIFICATE
import no.nav.emottak.sertifikatvalidator.model.SertifikatError
import org.apache.tomcat.util.codec.binary.Base64
import org.springframework.core.io.ClassPathResource
import org.springframework.core.io.FileSystemResource
import org.springframework.http.HttpStatus
import java.io.InputStream
import java.nio.charset.StandardCharsets


internal fun decodeBase64(base64String: String): ByteArray =
    try {
        Base64.decodeBase64(base64String)
    }
    catch (e: Exception) {
        throw SertifikatError(HttpStatus.BAD_REQUEST, FEIL_BASE64_X509CERTIFICATE)
    }


internal fun createInputstreamFromFileName(filnavn: String): InputStream =
    if (filnavn.startsWith("classpath")) {
        createInputstreamFromClasspath(filnavn.substringAfter(":"))
    } else {
        createInputstreamFromFile(filnavn.substringAfter(":"))
    }

private fun createInputstreamFromClasspath(filnavn: String) =
    ClassPathResource(filnavn).inputStream

private fun createInputstreamFromFile(filnavn: String) =
    FileSystemResource(filnavn).inputStream

internal fun getEnvVar(varName: String, defaultValue: String? = null) =
    System.getenv(varName) ?: defaultValue ?: throw RuntimeException("Missing required variable $varName")

internal fun getFileAsString(filePath: String) = String(createInputstreamFromFileName(filePath).readAllBytes(), StandardCharsets.UTF_8)