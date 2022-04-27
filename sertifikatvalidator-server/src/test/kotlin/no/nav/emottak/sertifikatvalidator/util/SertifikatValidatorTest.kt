package no.nav.emottak.sertifikatvalidator.util

import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_GYLDIG
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_REVOKERT
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_VALIDERING_OK
import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.SertifikatData
import no.nav.emottak.sertifikatvalidator.model.SertifikatError
import no.nav.emottak.sertifikatvalidator.model.SertifikatInfo
import no.nav.emottak.sertifikatvalidator.model.SertifikatStatus
import no.nav.emottak.sertifikatvalidator.model.SertifikatType
import no.nav.emottak.sertifikatvalidator.service.CRLChecker
import no.nav.emottak.sertifikatvalidator.service.OCSPChecker
import no.nav.emottak.sertifikatvalidator.service.SertifikatValidator
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.assertThrows
import org.mockito.Mockito
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.jwt.JwtDecoder
import java.security.cert.X509Certificate
import java.time.Instant
import javax.servlet.Filter


@SpringBootTest(
    properties = ["AZURE_APP_CLIENT_ID=test", "AZURE_APP_TENANT_ID=test"]
)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SertifikatValidatorTest {

    @Autowired
    private lateinit var sertifikatValidator: SertifikatValidator

    @MockBean
    private lateinit var ocspChecker: OCSPChecker

    @MockBean
    private lateinit var crlChecker: CRLChecker

    @MockBean
    private lateinit var jwtDecoder: JwtDecoder

    @MockBean(name = "springSecurityFilterChain")
    private lateinit var springSecurityFilterChain: Filter

    @Test
    @Disabled
    fun `Buypass rot personsertifikat validert`() {
        val filnavn = "classpath:buypass/BPCl3CaG2HTPS.cer"
        val gyldighetsdato = Instant.now()
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)
        val sertifikatData = SertifikatData(x509Certificate, filnavn)

        val sertifikatInfo = sertifikatValidator.validateCertificate(sertifikatData, gyldighetsdato)
        assert(sertifikatInfo.status == SertifikatStatus.OK)
        assert(sertifikatInfo.beskrivelse == SERTIFIKAT_VALIDERING_OK)
        log.info("SertifikatInfo: $sertifikatInfo")
    }

    @Test
    @Disabled
    fun `Buypass rotsertifikat validert`() {
        val filnavn = "classpath:buypass/BPCl3RootCaG2HT.cer"
        val gyldighetsdato = Instant.now()
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)
        val sertifikatData = SertifikatData(x509Certificate, filnavn)

        Mockito.`when`(ocspChecker.getOCSPStatus(sertifikatData)).thenReturn(createOCSPCheckerResponse(x509Certificate, SertifikatStatus.REVOKERT, SertifikatType.PERSONLIG, "12345678910", SERTIFIKAT_REVOKERT))

        val sertifikatInfo = sertifikatValidator.validateCertificate(sertifikatData, gyldighetsdato)
        assert(sertifikatInfo.status == SertifikatStatus.OK)
        assert(sertifikatInfo.beskrivelse == SERTIFIKAT_VALIDERING_OK)
        log.info("SertifikatInfo: $sertifikatInfo")
    }

    @Test
    //@Disabled
    fun `Buypass Gyldig sertifikat validert`() {
        val filnavn = "classpath:buypass/buypass_valid.cer"
        val gyldighetsdato = Instant.now()
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)
        val sertifikatData = SertifikatData(x509Certificate, filnavn)

        Mockito.`when`(ocspChecker.getOCSPStatus(sertifikatData)).thenReturn(createOCSPCheckerResponse(x509Certificate, SertifikatStatus.OK, SertifikatType.PERSONLIG, "12345678910", ""))

        val sertifikatInfo = sertifikatValidator.validateCertificate(sertifikatData, gyldighetsdato)
        assert(sertifikatInfo.status == SertifikatStatus.OK)
        assert(sertifikatInfo.beskrivelse == SERTIFIKAT_VALIDERING_OK)
        log.info("SertifikatInfo: $sertifikatInfo")
    }

    @Test
    //@Disabled //TODO
    fun `Buypass revokert sertifikat ikke validert`() {
        val filnavn = "classpath:buypass/buypass_revoked.cer"
        val gyldighetsdato = Instant.now()
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)
        val sertifikatData = SertifikatData(x509Certificate, filnavn)

        Mockito.`when`(ocspChecker.getOCSPStatus(sertifikatData)).thenReturn(createOCSPCheckerResponse(x509Certificate, SertifikatStatus.REVOKERT, SertifikatType.PERSONLIG, "12345678910", SERTIFIKAT_REVOKERT))

        val sertifikatInfo = sertifikatValidator.validateCertificate(sertifikatData, gyldighetsdato)
        assert(sertifikatInfo.status == SertifikatStatus.REVOKERT)
        assert(sertifikatInfo.beskrivelse == SERTIFIKAT_REVOKERT)
        log.info("SertifikatInfo: $sertifikatInfo")
    }

    @Test
    //@Disabled
    fun `Buypass expired sertifikat ikke validert`() {
        val filnavn = "classpath:buypass/buypass_expired.cer"
        val gyldighetsdato = Instant.now()
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)
        val sertifikatData = SertifikatData(x509Certificate, filnavn)

        val exception = assertThrows<SertifikatError> {
            sertifikatValidator.validateCertificate(sertifikatData, gyldighetsdato)
        }
        assert(exception.statusCode == HttpStatus.UNPROCESSABLE_ENTITY)
        assert(exception.message == SERTIFIKAT_IKKE_GYLDIG)
        log.info("SertifikatInfo: ${exception.sertifikatInfo}")
    }

    @Test
    //@Disabled
    fun `Buypass test4-autentiseringssertifikat-qceseal validert`() {
        val filnavn = "classpath:buypass/test4-autentiseringssertifikat-qceseal.cer"
        val gyldighetsdato = Instant.now()
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)
        val sertifikatData = SertifikatData(x509Certificate, filnavn)

        Mockito.`when`(ocspChecker.getOCSPStatus(sertifikatData)).thenReturn(createOCSPCheckerResponse(x509Certificate, SertifikatStatus.OK, SertifikatType.PERSONLIG, "12345678910", ""))

        val sertifikatInfo = sertifikatValidator.validateCertificate(sertifikatData, gyldighetsdato)
        assert(sertifikatInfo.status == SertifikatStatus.OK)
        assert(sertifikatInfo.beskrivelse == SERTIFIKAT_VALIDERING_OK)
        log.info("SertifikatInfo: $sertifikatInfo")
    }

    @Test
    //@Disabled
    fun `Buypass test4-autentiseringssertifikat-vid-europa validert`() {
        val filnavn = "classpath:buypass/test4-autentiseringssertifikat-vid-europa.cer"
        val gyldighetsdato = Instant.now()
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)
        val sertifikatData = SertifikatData(x509Certificate, filnavn)

        Mockito.`when`(ocspChecker.getOCSPStatus(sertifikatData)).thenReturn(createOCSPCheckerResponse(x509Certificate, SertifikatStatus.OK, SertifikatType.PERSONLIG, "12345678910", ""))

        val sertifikatInfo = sertifikatValidator.validateCertificate(sertifikatData, gyldighetsdato)
        assert(sertifikatInfo.status == SertifikatStatus.OK)
        assert(sertifikatInfo.beskrivelse == SERTIFIKAT_VALIDERING_OK)
        log.info("SertifikatInfo: $sertifikatInfo")
    }

    @Test
    //@Disabled
    fun `Buypass test4-signeringssertifikat-pid validert`() {
        val filnavn = "classpath:buypass/test4-signeringssertifikat-pid.cer"
        val gyldighetsdato = Instant.now()
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)
        val sertifikatData = SertifikatData(x509Certificate, filnavn)

        Mockito.`when`(ocspChecker.getOCSPStatus(sertifikatData)).thenReturn(createOCSPCheckerResponse(x509Certificate, SertifikatStatus.OK, SertifikatType.PERSONLIG, "12345678910", ""))

        val sertifikatInfo = sertifikatValidator.validateCertificate(sertifikatData, gyldighetsdato)
        assert(sertifikatInfo.status == SertifikatStatus.OK)
        assert(sertifikatInfo.beskrivelse == SERTIFIKAT_VALIDERING_OK)
        log.info("SertifikatInfo: $sertifikatInfo")
    }

    @Test
    //@Disabled
    fun `Buypass test4-signeringssertifikat-qceseal validert`() {
        val filnavn = "classpath:buypass/test4-signeringssertifikat-qceseal.cer"
        val gyldighetsdato = Instant.now()
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)
        val sertifikatData = SertifikatData(x509Certificate, filnavn)

        Mockito.`when`(ocspChecker.getOCSPStatus(sertifikatData)).thenReturn(createOCSPCheckerResponse(x509Certificate, SertifikatStatus.OK, SertifikatType.PERSONLIG, "12345678910", ""))

        val sertifikatInfo = sertifikatValidator.validateCertificate(sertifikatData, gyldighetsdato)
        assert(sertifikatInfo.status == SertifikatStatus.OK)
        assert(sertifikatInfo.beskrivelse == SERTIFIKAT_VALIDERING_OK)
        log.info("SertifikatInfo: $sertifikatInfo")
    }

    @Test
    //@Disabled
    fun `Buypass test4-signeringssertifikat-vid-europa validert`() {
        val filnavn = "classpath:buypass/test4-signeringssertifikat-vid-europa.cer"
        val gyldighetsdato = Instant.now()
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)
        val sertifikatData = SertifikatData(x509Certificate, filnavn)

        Mockito.`when`(ocspChecker.getOCSPStatus(sertifikatData)).thenReturn(createOCSPCheckerResponse(x509Certificate, SertifikatStatus.OK, SertifikatType.PERSONLIG, "12345678910", ""))

        val sertifikatInfo = sertifikatValidator.validateCertificate(sertifikatData, gyldighetsdato)
        assert(sertifikatInfo.status == SertifikatStatus.OK)
        assert(sertifikatInfo.beskrivelse == SERTIFIKAT_VALIDERING_OK)
        log.info("SertifikatInfo: $sertifikatInfo")
    }

    private fun createOCSPCheckerResponse(certificate: X509Certificate, status: SertifikatStatus, type: SertifikatType, ssn: String, beskrivelse: String): SertifikatInfo {
        return SertifikatInfo(
            serienummer = certificate.serialNumber.toString(),
            status = status,
            type = type,
            seid = getSEIDVersion(certificate),
            gyldigFra = formatDate(certificate.notBefore),
            gyldigTil = formatDate(certificate.notAfter),
            utsteder = certificate.issuerX500Principal.name,
            orgnummer = getOrganizationNumber(certificate),
            fnr = ssn,
            beskrivelse = beskrivelse,
            feilmelding = null
        )
    }
}