package no.nav.emottak.sertifikatvalidator.util

import no.nav.emottak.sertifikatvalidator.FEIL_X509CERTIFICATE
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_IKKE_GYLDIG_LENGER
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_REVOKERT
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_SELF_SIGNED
import no.nav.emottak.sertifikatvalidator.SERTIFIKAT_VALIDERING_OK
import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.SertifikatError
import no.nav.emottak.sertifikatvalidator.model.SertifikatInfo
import no.nav.emottak.sertifikatvalidator.model.SertifikatStatus
import no.nav.emottak.sertifikatvalidator.service.SertifikatValidator
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.assertThrows
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.HttpStatus
import org.springframework.web.server.ResponseStatusException
import java.time.Instant


@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SertifikatValidatorTest {

    @Autowired
    private lateinit var sertifikatValidator: SertifikatValidator

    @Test
    @Disabled
    fun `Revokert sertifikat ikke validert`() {
        val filnavn = "classpath:x509/aage_baertoemmer_nonrep_9423.cer"
        val gyldighetsdato = Instant.ofEpochMilli(1273500994000)
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)

        val sertifikatInfo = sertifikatValidator.validateCertificate(x509Certificate, gyldighetsdato)
        assert(sertifikatInfo.status == SertifikatStatus.REVOKERT)
        assert(sertifikatInfo.beskrivelse == SERTIFIKAT_REVOKERT)
    }

    @Test
    @Disabled
    fun `Utloept sertifikat ikke validert`() {
        val filnavn = "classpath:x509/astro_boy_expired_8414.cer"
        val gyldighetsdato = Instant.now()
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)

        val exception = assertThrows<SertifikatError> {
            sertifikatValidator.validateCertificate(x509Certificate, gyldighetsdato)
        }
        assert(exception.statusCode == HttpStatus.BAD_REQUEST)
        assert(exception.message == SERTIFIKAT_IKKE_GYLDIG_LENGER)
    }

    @Test
    @Disabled
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
    @Disabled
    fun `Gyldig sertifikat validert`() {
        val filnavn = "classpath:x509/hedda_taugbol_385187086391706896612464_nonrep.cer"
        val gyldighetsdato = Instant.ofEpochMilli(1431267394000)
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)

        val sertifikatInfo = sertifikatValidator.validateCertificate(x509Certificate, gyldighetsdato)
        assert(sertifikatInfo.status == SertifikatStatus.OK)
        assert(sertifikatInfo.beskrivelse == SERTIFIKAT_VALIDERING_OK)
    }

    @Test
    @Disabled
    fun `Gyldig NAV sertifikat validert`() {
        val filnavn = "classpath:x509/NAVTestEncrypt2021.cer"
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)

        val sertifikatInfo = sertifikatValidator.validateCertificate(x509Certificate, Instant.now())
        assert(sertifikatInfo.status == SertifikatStatus.OK)
        assert(sertifikatInfo.beskrivelse == SERTIFIKAT_VALIDERING_OK)
    }

    @Test
    @Disabled
    fun `Gyldig sertifikat validert 2`() {
        val filnavn = "classpath:x509/ingvild_sodal_2834285249931320560555_nonrep.cer"
        val gyldighetsdato = Instant.ofEpochMilli(1336659394000)
        val certificateInputstream = createInputstreamFromFileName(filnavn)
        val x509Certificate = createX509Certificate(certificateInputstream)

        val sertifikatInfo = sertifikatValidator.validateCertificate(x509Certificate, gyldighetsdato)
        assert(sertifikatInfo.status == SertifikatStatus.OK)
        assert(sertifikatInfo.beskrivelse == SERTIFIKAT_VALIDERING_OK)
    }

    @Test
    @Disabled
    fun `Korrupt sertifikatinput ikke validert`() {
        val filnavn = "classpath:x509/invalid_certificate_string.cer"
        val certificateInputstream = createInputstreamFromFileName(filnavn)

        val exception = assertThrows<SertifikatError> {
            createX509Certificate(certificateInputstream)
        }
        assert(exception.statusCode == HttpStatus.BAD_REQUEST)
        assert(exception.message == FEIL_X509CERTIFICATE)
    }


}