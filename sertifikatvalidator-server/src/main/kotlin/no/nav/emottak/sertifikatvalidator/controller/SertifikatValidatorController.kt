package no.nav.emottak.sertifikatvalidator.controller

import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.SertifikatData
import no.nav.emottak.sertifikatvalidator.model.SertifikatInfo
import no.nav.emottak.sertifikatvalidator.service.SertifikatValidator
import no.nav.emottak.sertifikatvalidator.util.createResponseEntity
import no.nav.emottak.sertifikatvalidator.util.createX509Certificate
import org.springframework.beans.factory.annotation.Value
import org.springframework.format.annotation.DateTimeFormat
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
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

    @Value("\${ssn.disable}")
    private var disableSSN: Boolean = true

    private val fnrTillattScope = "FNR_TILLATT"

    @PostMapping("/valider/sertifikat", consumes = [ MediaType.MULTIPART_FORM_DATA_VALUE ], produces = [ MediaType.APPLICATION_JSON_VALUE ])
    fun validerSertifikat(@RequestBody sertifikat: MultipartFile,
                          @RequestParam("gyldighetsdato") @DateTimeFormat(pattern ="yyyy-MM-dd") date: Date?,
                          @RequestParam("fnr") inkluderFnr: Boolean?
    ): ResponseEntity<SertifikatInfo> {
        val authentication = SecurityContextHolder.getContext().authentication as JwtAuthenticationToken
        val currentPrincipal = authentication.principal as Jwt
        log.info("claims: ${currentPrincipal.claims} type: ${authentication.javaClass.name} principal: ${authentication.principal.javaClass.name}")
        val uuid = sertifikat.originalFilename ?: "FILENAME_MISSING_GENERATED_THIS_${UUID.randomUUID()}"
        val x509Certificate = createX509Certificate(sertifikat.inputStream)
        val validityDate = date?.toInstant() ?: Instant.now()
        val sertifikatData = SertifikatData(x509Certificate, uuid, validityDate)
        val sertifikatInfo = sertifikatValidator.validateCertificate(sertifikatData)
        val fnr = if (disableSSN) {
            log.debug("ssn disabled, masking value")
            false
//        } else if (principal?.authorities?.first { it.authority == "SCOPE_$fnrTillattScope" } != null) {
//            log.debug("Klient ${principal.name} har scope $fnrTillattScope")
//            inkluderFnr ?: false
        } else {
            false
        }
        return createResponseEntity(sertifikatInfo, sertifikatData.uuid, fnr)
    }

}