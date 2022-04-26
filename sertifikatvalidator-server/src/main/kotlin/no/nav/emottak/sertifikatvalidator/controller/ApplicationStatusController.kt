package no.nav.emottak.sertifikatvalidator.controller

import no.nav.emottak.sertifikatvalidator.model.CRLs
import no.nav.emottak.sertifikatvalidator.service.CRLChecker
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

@RestController
class ApplicationStatusController(val crlChecker: CRLChecker) {

    @GetMapping("/internal/crl", produces = [MediaType.APPLICATION_JSON_VALUE])
    @ResponseStatus(HttpStatus.OK)
    fun getCrlList(): ResponseEntity<CRLs> {
        return ResponseEntity.ok(crlChecker.crls)
    }

    @GetMapping("/internal/crl/update", produces = [MediaType.APPLICATION_JSON_VALUE])
    @ResponseStatus(HttpStatus.OK)
    fun updateCrlList(): ResponseEntity<CRLs> {
        crlChecker.updateCRLs()
        return ResponseEntity.ok(crlChecker.crls)
    }

}