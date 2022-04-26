package no.nav.emottak.sertifikatvalidator.controller

import no.nav.emottak.sertifikatvalidator.model.CRLs
import no.nav.emottak.sertifikatvalidator.model.ServerStatus
import no.nav.emottak.sertifikatvalidator.service.CRLChecker
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/status")
class ApplicationStatusController(val crlChecker: CRLChecker) {

    @GetMapping("/server/klient", produces = [MediaType.APPLICATION_JSON_VALUE])
    @ResponseStatus(HttpStatus.OK)
    fun klientServerStatus(@RequestParam("buildMode") buildMode: Boolean?): ResponseEntity<ServerStatus> {
        val validator = no.nav.emottak.sertifikatvalidator.klient.SertifikatValidator()
        val serverStatus = validator.checkServerCompatibility()
        return if (serverStatus.kompatibel) {
            ResponseEntity.ok(serverStatus)
        } else {
            ResponseEntity.internalServerError().body(serverStatus)
        }
    }

    @GetMapping("/crl", produces = [MediaType.APPLICATION_JSON_VALUE])
    @ResponseStatus(HttpStatus.OK)
    fun getCrlList(): ResponseEntity<CRLs> {
        return ResponseEntity.ok(crlChecker.crls)
    }

    @GetMapping("/crl/update", produces = [MediaType.APPLICATION_JSON_VALUE])
    @ResponseStatus(HttpStatus.OK)
    fun updateCrlList(): ResponseEntity<CRLs> {
        crlChecker.updateCRLs()
        return ResponseEntity.ok(crlChecker.crls)
    }

}