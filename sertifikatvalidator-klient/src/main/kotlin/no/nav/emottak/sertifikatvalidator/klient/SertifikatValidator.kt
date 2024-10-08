package no.nav.emottak.sertifikatvalidator.klient

import no.nav.emottak.sertifikatvalidator.model.SertifikatInfo
import no.nav.emottak.sertifikatvalidator.model.SertifikatStatus
import no.nav.emottak.sertifikatvalidator.model.ServerStatus
import okhttp3.MultipartBody
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale
import java.util.UUID

open class SertifikatValidator(): MicroserviceClient() {

    var buildMode = false

    fun valider(sertifikat: ByteArray): SertifikatInfo {
        return valider(sertifikat, UUID.randomUUID().toString())
    }

    fun valider(sertifikat: ByteArray, messageId: String): SertifikatInfo {
        return valider(sertifikat, messageId, false)
    }

    fun valider(sertifikat: ByteArray, messageId: String, inkluderFnr: Boolean): SertifikatInfo {
        return valider(sertifikat, messageId, Instant.now(), inkluderFnr)
    }

    fun valider(sertifikat: ByteArray, messageId: String, gyldighetsdato: Instant, inkluderFnr: Boolean): SertifikatInfo {
        val url = when (buildMode) {
            true -> "http://localhost:8080/api/valider/sertifikat"
            false -> serviceUrl
        }
        try {
            val requestBody = createMultipartBodyRequest(sertifikat, messageId)
            val request = Request.Builder()
                .url("$url?gyldighetsdato=${formatInstant(gyldighetsdato)}&inkluderFnr=$inkluderFnr")
                .addHeader("Content-Type", "multipart/form-data")
                .addHeader("Accept", "application/json")
                .addHeader("Authorization", "Bearer ${getAccessToken()}")
                .post(requestBody)
                .build()
            return postRequestToService(url, request, SertifikatInfo::class.java, 0, messageId)
        } catch (e: Exception) {
            log.error("UUID $messageId feilet: ${e.localizedMessage}")
            log.debug(e.localizedMessage, e)
            throw e
        }
    }

    private fun createMultipartBodyRequest(
        sertifikat: ByteArray,
        messageId: String,
    ): MultipartBody {
        val requestBody = MultipartBody.Builder().setType(MultipartBody.FORM)
        requestBody.addFormDataPart("sertifikat", messageId, sertifikat.toRequestBody())
        return requestBody.build()
    }

    override fun checkServerCompatibility(): ServerStatus {
        try {
            val testFile = this::class.java.classLoader.getResourceAsStream("buypass_valid.cer").readBytes()
            val sertifikatInfo = valider(testFile, "COMPATIBILITY_CHECK_${LocalDateTime.now()}")
            return createServerStatusResponse(sertifikatInfo.status == SertifikatStatus.OK)
        } catch (e: Exception) {
            return createServerStatusErrorResponse(e)
        }
    }

}

private fun formatInstant(instant: Instant): String {
    val formatter = DateTimeFormatter.ISO_DATE
        .withLocale(Locale("NB"))
        .withZone(ZoneId.systemDefault())
    return formatter.format(instant)
}
