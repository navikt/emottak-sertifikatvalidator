package no.nav.emottak.sertifikatvalidator

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.scheduling.annotation.EnableScheduling

val log: Logger = LoggerFactory.getLogger("no.nav.emottak.sertifikatvalidator")

@SpringBootApplication
@EnableScheduling
class SertifikatvalidatorApplication

fun main(args: Array<String>) {
	runApplication<SertifikatvalidatorApplication>(*args)
}
