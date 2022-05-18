package no.nav.emottak.sertifikatvalidator.controller

import net.logstash.logback.marker.Markers
import no.nav.emottak.sertifikatvalidator.UKJENT_FEIL
import no.nav.emottak.sertifikatvalidator.model.SertifikatError

import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.SertifikatInfo
import no.nav.emottak.sertifikatvalidator.model.SertifikatStatus
import no.nav.emottak.sertifikatvalidator.util.createFieldMap
import no.nav.emottak.sertifikatvalidator.util.createSertifikatInfoFromCertificate
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import javax.servlet.http.HttpServletRequest


@ControllerAdvice
internal class SertifikatExceptionHandler {

    @ExceptionHandler(SertifikatError::class)
    fun handleSertifikatError(req: HttpServletRequest, ex: SertifikatError): ResponseEntity<SertifikatInfo?> {
        val uuid = ex.sertifikatData?.uuid ?: "UKJENT ID"
        val message = ex.localizedMessage
        if (ex.logStackTrace) {
            log.error("UUID $uuid $message", ex)
        }
        else {
            log.error("UUID $uuid $message")
            log.debug("Logging level satt til DEBUG, logger stacktrace likevel")
            log.debug("UUID $uuid $message", ex)
        }
        val body = createResponseBody(ex)
        log.warn(Markers.appendEntries(createFieldMap(ex.statusCode, body, ex.javaClass.canonicalName)), "Sertifikatvalidering response returnert")
        return ResponseEntity.status(ex.statusCode).body(body)
    }

    private fun createResponseBody(ex: SertifikatError): SertifikatInfo? {
        return ex.sertifikatInfo
            ?: if (ex.sertifikatData != null) {
                createSertifikatInfoFromCertificate(ex.sertifikatData, SertifikatStatus.UKJENT, UKJENT_FEIL)
            }
            else {
                null
            }

    }
}