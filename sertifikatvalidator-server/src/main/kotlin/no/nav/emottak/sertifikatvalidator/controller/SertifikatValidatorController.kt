package no.nav.emottak.sertifikatvalidator.controller

import no.nav.emottak.sertifikatvalidator.model.SertifikatInfo
import no.nav.emottak.sertifikatvalidator.model.ServerStatus
import no.nav.emottak.sertifikatvalidator.service.SertifikatValidator
import no.nav.emottak.sertifikatvalidator.util.createResponseEntity
import no.nav.emottak.sertifikatvalidator.util.createX509Certificate
import no.nav.emottak.sertifikatvalidator.util.decodeBase64
import org.springframework.format.annotation.DateTimeFormat
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.multipart.MultipartFile
import java.time.Instant
import java.util.Date


@RestController
@RequestMapping("/api")
class SertifikatValidatorController(val sertifikatValidator: SertifikatValidator) {

    @PostMapping("/valider/sertifikat", consumes = [ MediaType.MULTIPART_FORM_DATA_VALUE ], produces = [ MediaType.APPLICATION_JSON_VALUE ])
    fun validerSertifikat(@RequestBody certificate: MultipartFile,
                          @RequestParam("gyldighetsdato") @DateTimeFormat(pattern ="yyyy-MM-dd") date: Date?
    ): ResponseEntity<SertifikatInfo> {
        val x509Certificate = createX509Certificate(certificate.inputStream)
        val validityDate = date?.toInstant() ?: Instant.now()
        val sertifikatInfo = sertifikatValidator.validateCertificate(x509Certificate, validityDate)
        return createResponseEntity(sertifikatInfo)
    }

}