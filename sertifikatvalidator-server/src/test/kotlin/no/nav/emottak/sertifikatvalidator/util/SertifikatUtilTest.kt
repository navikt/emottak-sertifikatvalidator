package no.nav.emottak.sertifikatvalidator.util

import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.SEIDVersion
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.springframework.core.io.support.PathMatchingResourcePatternResolver
import java.security.cert.X509Certificate

class SertifikatUtilTest {

    @Test
    fun `Buypass batch test SEID1 certificates`() {
        val certificateFolder = "classpath:buypass/SEID1/**"
        val fileList = PathMatchingResourcePatternResolver().getResources(certificateFolder)
        fileList.forEach {
            val filnavn = it.filename ?: "Ukjent fil"
            log.info("Tester $filnavn")
            val x509Certificate = createX509Certificate(it.inputStream)
            assertCertificateOfSEIDVersionHasOrgnumberIfOrgCertAndNotOtherwise(filnavn, x509Certificate, SEIDVersion.SEID10)
        }
    }

    @Test
    @Disabled //TODO
    fun `Commfides batch test SEID1 certificates`() {
        val certificateFolder = "classpath:commfides/SEID1/**"
        val fileList = PathMatchingResourcePatternResolver().getResources(certificateFolder)
        fileList.forEach {
            val filnavn = it.filename ?: "Ukjent fil"
            log.info("Tester $filnavn")
            val x509Certificate = createX509Certificate(it.inputStream)
            assertCertificateOfSEIDVersionHasOrgnumberIfOrgCertAndNotOtherwise(filnavn, x509Certificate, SEIDVersion.SEID20)
        }
    }

    @Test
    fun `Buypass batch test SEID2 certificates`() {
        val certificateFolder = "classpath:buypass/SEID2/**"
        val fileList = PathMatchingResourcePatternResolver().getResources(certificateFolder)
        fileList.forEach {
            val filnavn = it.filename ?: "Ukjent fil"
            log.info("Tester $filnavn")
            val x509Certificate = createX509Certificate(it.inputStream)
            assertCertificateOfSEIDVersionHasOrgnumberIfOrgCertAndNotOtherwise(filnavn, x509Certificate, SEIDVersion.SEID20)
        }
    }

    @Test
    fun `Commfides batch test SEID2 certificates`() {
        val certificateFolder = "classpath:commfides/SEID2/**"
        val fileList = PathMatchingResourcePatternResolver().getResources(certificateFolder)
        fileList.forEach {
            val filnavn = it.filename ?: "Ukjent fil"
            log.info("Tester $filnavn")
            val x509Certificate = createX509Certificate(it.inputStream)
            assertCertificateOfSEIDVersionHasOrgnumberIfOrgCertAndNotOtherwise(filnavn, x509Certificate, SEIDVersion.SEID20)
        }
    }

    private fun assertCertificateOfSEIDVersionHasOrgnumberIfOrgCertAndNotOtherwise(
        filename: String, certificate: X509Certificate, wantedSEIDVersion: SEIDVersion
    ) {
        val seidVersion = getSEIDVersion(certificate)
        val isVirksomhetssertifikat = isVirksomhetssertifikat(certificate)
        val orgNumber = getOrganizationNumber(certificate)
        log.debug(certificate.toString())
        log.info("Filnavn: $filename SEID: $seidVersion VIRKSOMHETSSERTIFIKAT: $isVirksomhetssertifikat ORG: $orgNumber")

        assert(seidVersion == wantedSEIDVersion)
        if (isVirksomhetssertifikat) {
            assert(orgNumber != null)
        } else {
            assert(orgNumber == null)
        }
    }
}