package no.nav.emottak.sertifikatvalidator.controller

import no.nav.emottak.sertifikatvalidator.model.CRLStatus
import no.nav.emottak.sertifikatvalidator.model.ServerStatus
import no.nav.emottak.sertifikatvalidator.service.CRLChecker
import no.nav.emottak.sertifikatvalidator.service.SsnCache
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/internal/status")
class ApplicationStatusController(val crlChecker: CRLChecker, val ssnCache: SsnCache) {

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
    fun getCrlList(): ResponseEntity<List<CRLStatus>> {
        val crlsList = crlChecker.certificateAuthorities.caList.stream().map { crlHolder -> CRLStatus(CAHolder = crlHolder) }.toList()
        return ResponseEntity.ok(crlsList)
    }

    @GetMapping("/crl/update", produces = [MediaType.APPLICATION_JSON_VALUE])
    @ResponseStatus(HttpStatus.OK)
    fun updateCrlList(): ResponseEntity<List<CRLStatus>> {
        crlChecker.updateCRLs()
        return getCrlList()
    }

    @GetMapping("/fnr/cache/count", produces = [MediaType.APPLICATION_JSON_VALUE])
    @ResponseStatus(HttpStatus.OK)
    fun getFnrCounter(): ResponseEntity<Int> {
        return ResponseEntity.ok(ssnCache.cacheCount())
    }

}