package no.nav.emottak.sertifikatvalidator.controller

import no.nav.emottak.sertifikatvalidator.UKJENT_FEIL
import no.nav.emottak.sertifikatvalidator.model.SertifikatError

import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.SertifikatInfo
import no.nav.emottak.sertifikatvalidator.model.SertifikatStatus
import no.nav.emottak.sertifikatvalidator.util.createSertifikatInfoFromX509Certificate
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import javax.servlet.http.HttpServletRequest


@ControllerAdvice
internal class SertifikatExceptionHandler {

    @ExceptionHandler(SertifikatError::class)
    fun handleSertifikatError(req: HttpServletRequest, ex: SertifikatError): ResponseEntity<SertifikatInfo?> {
        log.error(ex.message, ex)
        val body = createResponseBody(ex)
        return ResponseEntity.status(ex.statusCode).body(body)
    }

    private fun createResponseBody(ex: SertifikatError): SertifikatInfo? {
        return ex.sertifikatInfo
            ?: if (ex.certificate != null) {
                createSertifikatInfoFromX509Certificate(ex.certificate, SertifikatStatus.UKJENT, UKJENT_FEIL)
            }
            else {
                null
            }

    }
}