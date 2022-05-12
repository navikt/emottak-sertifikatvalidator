package no.nav.emottak.sertifikatvalidator.controller

import no.nav.emottak.sertifikatvalidator.model.SertifikatData
import no.nav.emottak.sertifikatvalidator.model.SertifikatInfo
import no.nav.emottak.sertifikatvalidator.service.SertifikatValidator
import no.nav.emottak.sertifikatvalidator.util.createResponseEntity
import no.nav.emottak.sertifikatvalidator.util.createX509Certificate
import org.springframework.format.annotation.DateTimeFormat
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.multipart.MultipartFile
import java.time.Instant
import java.util.Date
import java.util.UUID


@RestController
@RequestMapping("/api")
class SertifikatValidatorController(val sertifikatValidator: SertifikatValidator) {

    @PostMapping("/valider/sertifikat", consumes = [ MediaType.MULTIPART_FORM_DATA_VALUE ], produces = [ MediaType.APPLICATION_JSON_VALUE ])
    fun validerSertifikat(@RequestBody certificate: MultipartFile,
                          @RequestParam("gyldighetsdato") @DateTimeFormat(pattern ="yyyy-MM-dd") date: Date?
    ): ResponseEntity<SertifikatInfo> {
        val uuid = certificate.originalFilename ?: "FILENAME_MISSING_GENERATED_THIS_${UUID.randomUUID()}"
        val x509Certificate = createX509Certificate(certificate.inputStream)
        val validityDate = date?.toInstant() ?: Instant.now()
        val sertifikatData = SertifikatData(x509Certificate, uuid, validityDate)
        val sertifikatInfo = sertifikatValidator.validateCertificate(sertifikatData)
        return createResponseEntity(sertifikatInfo)
    }

}