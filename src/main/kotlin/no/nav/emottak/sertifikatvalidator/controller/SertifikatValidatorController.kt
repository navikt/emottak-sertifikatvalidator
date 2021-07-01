package no.nav.emottak.sertifikatvalidator.controller

import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_VALIDERING_FEILET
import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.SertifikatInfo
import no.nav.emottak.sertifikatvalidator.model.SertifikatStatus
import no.nav.emottak.sertifikatvalidator.model.SertifikatType
import no.nav.emottak.sertifikatvalidator.service.validateCertificate
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
class SertifikatValidatorController() {

    @PostMapping("/valider/sertifikat")
    fun validerSertifikat(@RequestBody certificateBase64: String,
                          @RequestParam("dato") date: Date?): ResponseEntity<SertifikatInfo> {
        val decodedCertificate = decodeBase64(certificateBase64)
        val x509Certificate = createX509Certificate(decodedCertificate.inputStream())
        return try {
            val validityDate = date?.toInstant() ?: Instant.now()
            createResponseEntity(validateCertificate(x509Certificate, validityDate))
        }
        catch (e: Exception) {
            log.error(SERTIFIKAT_VALIDERING_FEILET, e)
            createResponseEntity(SertifikatInfo(
                serienummer = x509Certificate.serialNumber.toString(),
                status = SertifikatStatus.FEIL_MED_TJENESTEN,
                type = SertifikatType.PERSONLIG,
                utsteder = x509Certificate.issuerX500Principal.getName(),
                fnr = null,
                beskrivelse = SERTIFIKAT_VALIDERING_FEILET,
                feilmelding = e.localizedMessage)
            )
        }
    }

}