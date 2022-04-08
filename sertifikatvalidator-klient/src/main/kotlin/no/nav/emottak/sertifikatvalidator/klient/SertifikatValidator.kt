package no.nav.emottak.sertifikatvalidator.klient

import no.nav.emottak.sertifikatvalidator.model.SertifikatInfo
import no.nav.emottak.sertifikatvalidator.model.SertifikatStatus
import no.nav.emottak.sertifikatvalidator.model.ServerStatus
import okhttp3.MultipartBody
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.time.Instant
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
        return valider(sertifikat, messageId, Instant.now())
    }

    fun valider(sertifikat: ByteArray, messageId: String, gyldighetsdato: Instant): SertifikatInfo {
        val url = when (buildMode) {
            true -> "http://localhost:8080/api/valider/sertifikat"
            false -> serviceUrl
        }
        try {
            val requestBody = createMultipartBodyRequest(sertifikat, messageId)
            val request = Request.Builder()
                .url("$url?gyldighetsdato=${formatInstant(gyldighetsdato)}")
                .addHeader("Content-Type", "multipart/form-data")
                .addHeader("Accept", "application/json")
                .addHeader("Authorization", "Bearer ${accessToken}")
                .post(requestBody)
                .build()
            return postRequestToService(url, request, SertifikatInfo::class.java)
        } catch (e: Exception) {
            log.error("Ukjent feil ved kall til $url", e)
            throw e
        }
    }

    private fun createMultipartBodyRequest(
        sertifikat: ByteArray,
        messageId: String,
    ): MultipartBody {
        val requestBody = MultipartBody.Builder().setType(MultipartBody.FORM)
        requestBody.addFormDataPart("certificate", messageId, sertifikat.toRequestBody())
        return requestBody.build()
    }

    override fun checkServerCompatibility(): ServerStatus {
        try {
            val testFile = this::class.java.classLoader.getResourceAsStream("buypass_valid.cer").readAllBytes()
            val sertifikatInfo = valider(testFile)
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
