package no.nav.emottak.sertifikatvalidator.controller

import no.nav.emottak.sertifikatvalidator.model.SertifikatInfo
import no.nav.emottak.sertifikatvalidator.service.SertifikatValidator
import no.nav.emottak.sertifikatvalidator.util.createResponseEntity
import no.nav.emottak.sertifikatvalidator.util.createX509Certificate
import no.nav.emottak.sertifikatvalidator.util.decodeBase64
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.time.Instant
import java.util.Date


@RestController
@RequestMapping("/api")
class SertifikatValidatorController(val sertifikatValidator: SertifikatValidator) {

    @PostMapping("/valider/sertifikat")
    fun validerSertifikat(@RequestBody certificateBase64: String,
                          @RequestParam("dato") date: Date?): ResponseEntity<SertifikatInfo> {
        val decodedCertificate = decodeBase64(certificateBase64)
        val x509Certificate = createX509Certificate(decodedCertificate.inputStream())
        val validityDate = date?.toInstant() ?: Instant.now()
        val sertifikatInfo = sertifikatValidator.validateCertificate(x509Certificate, validityDate)
        return createResponseEntity(sertifikatInfo)
    }

}