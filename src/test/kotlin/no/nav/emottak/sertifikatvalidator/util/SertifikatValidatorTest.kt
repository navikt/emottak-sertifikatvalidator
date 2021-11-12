package no.nav.emottak.sertifikatvalidator.util

import no.nav.emottak.sertifikatvalidator.FEIL_X509CERTIFICATE
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_GYLDIG
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_REVOKERT
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_SELF_SIGNED
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_VALIDERING_OK
import no.nav.emottak.sertifikatvalidator.log
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
import java.security.cert.X509Certificate
import java.time.Instant


@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SertifikatValidatorTest {

    @Autowired
    private lateinit var sertifikatValidator: SertifikatValidator

    @MockBean
    private lateinit var ocspChecker: OCSPChecker

    @MockBean
    private lateinit var crlChecker: CRLChecker

    @Test
    //@Disabled
    fun `Revokert sertifikat ikke validert`() {
        val filnavn = "classpath:x509/aage_baertoemmer_nonrep_9423.cer"
        val gyldighetsdato = Instant.ofEpochMilli(1273500994000)
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)

        Mockito.`when`(ocspChecker.getOCSPStatus(x509Certificate)).thenReturn(createOCSPCheckerResponse(x509Certificate, SertifikatStatus.REVOKERT, SertifikatType.PERSONLIG, "12345678910", SERTIFIKAT_REVOKERT))

        val sertifikatInfo = sertifikatValidator.validateCertificate(x509Certificate, gyldighetsdato)
        assert(sertifikatInfo.status == SertifikatStatus.REVOKERT)
        assert(sertifikatInfo.beskrivelse == SERTIFIKAT_REVOKERT)
        log.info("SertifikatInfo: $sertifikatInfo")
    }

    @Test
    //@Disabled
    fun `Utloept sertifikat ikke validert`() {
        val filnavn = "classpath:x509/astro_boy_expired_8414.cer"
        val gyldighetsdato = Instant.now()
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)

        val exception = assertThrows<SertifikatError> {
            sertifikatValidator.validateCertificate(x509Certificate, gyldighetsdato)
        }
        assert(exception.statusCode == HttpStatus.BAD_REQUEST)
        assert(exception.message == SERTIFIKAT_IKKE_GYLDIG)
    }

    @Test
    //@Disabled
    fun `Selvsignert sertifikat ikke validert`() {
        val filnavn = "classpath:x509/buypass_test_1.cer"
        val gyldighetsdato = Instant.ofEpochMilli(1115734594000)
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)

        val exception = assertThrows<SertifikatError> {
            sertifikatValidator.validateCertificate(x509Certificate, gyldighetsdato)
        }

        assert(exception.statusCode == HttpStatus.BAD_REQUEST)
        assert(exception.message == SERTIFIKAT_SELF_SIGNED)
    }

    @Test
    //@Disabled
    fun `Gyldig sertifikat validert`() {
        val filnavn = "classpath:x509/hedda_taugbol_385187086391706896612464_nonrep.cer"
        val gyldighetsdato = Instant.ofEpochMilli(1431267394000)
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)

        Mockito.`when`(ocspChecker.getOCSPStatus(x509Certificate)).thenReturn(createOCSPCheckerResponse(x509Certificate, SertifikatStatus.OK, SertifikatType.PERSONLIG, "12345678910", ""))

        val sertifikatInfo = sertifikatValidator.validateCertificate(x509Certificate, gyldighetsdato)
        assert(sertifikatInfo.status == SertifikatStatus.OK)
        assert(sertifikatInfo.beskrivelse == SERTIFIKAT_VALIDERING_OK)
        log.info("SertifikatInfo: $sertifikatInfo")
    }

    @Test
    @Disabled
    fun `Gyldig NAV sertifikat validert`() {
        val filnavn = "classpath:x509/NAVTestEncrypt2021.cer"
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)

        Mockito.`when`(ocspChecker.getOCSPStatus(x509Certificate)).thenReturn(createOCSPCheckerResponse(x509Certificate, SertifikatStatus.OK, SertifikatType.PERSONLIG, "12345678910", ""))

        val sertifikatInfo = sertifikatValidator.validateCertificate(x509Certificate, Instant.now())
        assert(sertifikatInfo.status == SertifikatStatus.OK)
        assert(sertifikatInfo.beskrivelse == SERTIFIKAT_VALIDERING_OK)
        log.info("SertifikatInfo: $sertifikatInfo")
    }

    @Test
    //@Disabled
    fun `Gyldig sertifikat validert 2`() {
        val filnavn = "classpath:x509/ingvild_sodal_2834285249931320560555_nonrep.cer"
        val gyldighetsdato = Instant.ofEpochMilli(1336659394000)
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)

        Mockito.`when`(ocspChecker.getOCSPStatus(x509Certificate)).thenReturn(createOCSPCheckerResponse(x509Certificate, SertifikatStatus.OK, SertifikatType.PERSONLIG, "12345678910", ""))

        val sertifikatInfo = sertifikatValidator.validateCertificate(x509Certificate, gyldighetsdato)
        assert(sertifikatInfo.status == SertifikatStatus.OK)
        assert(sertifikatInfo.beskrivelse == SERTIFIKAT_VALIDERING_OK)
        log.info("SertifikatInfo: $sertifikatInfo")
    }

    @Test
    //@Disabled
    fun `Korrupt sertifikatinput ikke validert`() {
        val filnavn = "classpath:x509/invalid_certificate_string.cer"
        val certificateInputstream = createInputstreamFromFileName(filnavn)

        val exception = assertThrows<SertifikatError> {
            createX509Certificate(certificateInputstream)
        }
        assert(exception.statusCode == HttpStatus.BAD_REQUEST)
        assert(exception.message == FEIL_X509CERTIFICATE)
    }

    @Test
    @Disabled
    fun `Buypass rot personsertifikat validert`() {
        val filnavn = "classpath:buypass/BPCl3CaG2HTPS.cer"
        val gyldighetsdato = Instant.now()
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)

        val sertifikatInfo = sertifikatValidator.validateCertificate(x509Certificate, gyldighetsdato)
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

        Mockito.`when`(ocspChecker.getOCSPStatus(x509Certificate)).thenReturn(createOCSPCheckerResponse(x509Certificate, SertifikatStatus.REVOKERT, SertifikatType.PERSONLIG, "12345678910", SERTIFIKAT_REVOKERT))

        val sertifikatInfo = sertifikatValidator.validateCertificate(x509Certificate, gyldighetsdato)
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

        Mockito.`when`(ocspChecker.getOCSPStatus(x509Certificate)).thenReturn(createOCSPCheckerResponse(x509Certificate, SertifikatStatus.OK, SertifikatType.PERSONLIG, "12345678910", ""))

        val sertifikatInfo = sertifikatValidator.validateCertificate(x509Certificate, gyldighetsdato)
        assert(sertifikatInfo.status == SertifikatStatus.OK)
        assert(sertifikatInfo.beskrivelse == SERTIFIKAT_VALIDERING_OK)
        log.info("SertifikatInfo: $sertifikatInfo")
    }

    @Test
    //@Disabled
    fun `Buypass revokert sertifikat ikke validert`() {
        val filnavn = "classpath:buypass/buypass_revoked.cer"
        val gyldighetsdato = Instant.now()
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)

        Mockito.`when`(ocspChecker.getOCSPStatus(x509Certificate)).thenReturn(createOCSPCheckerResponse(x509Certificate, SertifikatStatus.REVOKERT, SertifikatType.PERSONLIG, "12345678910", SERTIFIKAT_REVOKERT))

        val sertifikatInfo = sertifikatValidator.validateCertificate(x509Certificate, gyldighetsdato)
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

        val exception = assertThrows<SertifikatError> {
            sertifikatValidator.validateCertificate(x509Certificate, gyldighetsdato)
        }
        assert(exception.statusCode == HttpStatus.BAD_REQUEST)
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

        Mockito.`when`(ocspChecker.getOCSPStatus(x509Certificate)).thenReturn(createOCSPCheckerResponse(x509Certificate, SertifikatStatus.OK, SertifikatType.PERSONLIG, "12345678910", ""))

        val sertifikatInfo = sertifikatValidator.validateCertificate(x509Certificate, gyldighetsdato)
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

        Mockito.`when`(ocspChecker.getOCSPStatus(x509Certificate)).thenReturn(createOCSPCheckerResponse(x509Certificate, SertifikatStatus.OK, SertifikatType.PERSONLIG, "12345678910", ""))

        val sertifikatInfo = sertifikatValidator.validateCertificate(x509Certificate, gyldighetsdato)
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

        Mockito.`when`(ocspChecker.getOCSPStatus(x509Certificate)).thenReturn(createOCSPCheckerResponse(x509Certificate, SertifikatStatus.OK, SertifikatType.PERSONLIG, "12345678910", ""))

        val sertifikatInfo = sertifikatValidator.validateCertificate(x509Certificate, gyldighetsdato)
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

        Mockito.`when`(ocspChecker.getOCSPStatus(x509Certificate)).thenReturn(createOCSPCheckerResponse(x509Certificate, SertifikatStatus.OK, SertifikatType.PERSONLIG, "12345678910", ""))

        val sertifikatInfo = sertifikatValidator.validateCertificate(x509Certificate, gyldighetsdato)
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

        Mockito.`when`(ocspChecker.getOCSPStatus(x509Certificate)).thenReturn(createOCSPCheckerResponse(x509Certificate, SertifikatStatus.OK, SertifikatType.PERSONLIG, "12345678910", ""))

        val sertifikatInfo = sertifikatValidator.validateCertificate(x509Certificate, gyldighetsdato)
        assert(sertifikatInfo.status == SertifikatStatus.OK)
        assert(sertifikatInfo.beskrivelse == SERTIFIKAT_VALIDERING_OK)
        log.info("SertifikatInfo: $sertifikatInfo")
    }

    private fun createOCSPCheckerResponse(certificate: X509Certificate, status: SertifikatStatus, type: SertifikatType, ssn: String, beskrivelse: String): SertifikatInfo {
        return SertifikatInfo(
            certificate = certificate,
            status = status,
            type = type,
            orgnummer = getOrganizationNumber(certificate),
            fnr = ssn,
            beskrivelse = beskrivelse,
            feilmelding = null
        )
    }
}