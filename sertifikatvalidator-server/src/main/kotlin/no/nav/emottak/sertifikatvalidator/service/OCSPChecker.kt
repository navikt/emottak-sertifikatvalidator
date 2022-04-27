package no.nav.emottak.sertifikatvalidator.service

import no.nav.emottak.sertifikatvalidator.FAILED_TO_GENERATE_REVOCATION_REQUEST
import no.nav.emottak.sertifikatvalidator.OCSP_SIGNATURE_VERIFICATION_FAILED
import no.nav.emottak.sertifikatvalidator.OCSP_VERIFICATION_EMPTY_RESPONSE
import no.nav.emottak.sertifikatvalidator.OCSP_VERIFICATION_UKJENT_FEIL
import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.SertifikatData
import no.nav.emottak.sertifikatvalidator.model.SertifikatError
import no.nav.emottak.sertifikatvalidator.model.SertifikatInfo
import no.nav.emottak.sertifikatvalidator.util.KeyStoreHandler
import no.nav.emottak.sertifikatvalidator.util.createSertifikatInfoFromOCSPResponse
import no.nav.emottak.sertifikatvalidator.util.getAuthorityInfoAccess
import no.nav.emottak.sertifikatvalidator.util.getAuthorityInfoAccessObject
import no.nav.emottak.sertifikatvalidator.util.isVirksomhetssertifikat
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.RFC4519Style
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.ExtensionsGenerator
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.ocsp.BasicOCSPResp
import org.bouncycastle.cert.ocsp.CertificateID
import org.bouncycastle.cert.ocsp.OCSPException
import org.bouncycastle.cert.ocsp.OCSPReq
import org.bouncycastle.cert.ocsp.OCSPReqBuilder
import org.bouncycastle.cert.ocsp.OCSPResp
import org.bouncycastle.cert.ocsp.SingleResp
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Service
import org.springframework.web.client.RestTemplate
import org.springframework.web.server.ResponseStatusException
import java.io.IOException
import java.math.BigInteger
import java.security.cert.X509Certificate

@Service
class OCSPChecker(val webClient: RestTemplate) {

    private val ACCESS_IDENTIFIER_OCSP = ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1")
    private val SSN_POLICY_ID = ASN1ObjectIdentifier("2.16.578.1.16.3.2")
    private val bcProvider = BouncyCastleProvider()

    fun getOCSPStatus(sertifikatData: SertifikatData): SertifikatInfo {
        val certificate = sertifikatData.sertifikat
        return try {
            val certificateIssuer = certificate.issuerX500Principal.name
            val ocspResponderCertificate = getOcspResponderCertificate(certificateIssuer)

            val request: OCSPReq = createOCSPRequest(certificate, ocspResponderCertificate)
            val response = postOCSPRequest(getOCSPUrl(certificate), request.encoded)
            decodeResponse(response, certificate, request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce), ocspResponderCertificate)
        } catch (e: SertifikatError) {
            throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, e.localizedMessage, sertifikatData, e, e.logStackTrace)
        } catch (e: Exception) {
            throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, e.localizedMessage, sertifikatData, e)
        }
    }

    private fun decodeResponse(response: OCSPResp, certificate: X509Certificate, requestNonce: Extension, ocspResponderCertificate: X509Certificate): SertifikatInfo {

        checkOCSPResponseStatus(response.status)

        val basicOCSPResponse: BasicOCSPResp = getBasicOCSPResp(response)

        verifyNonce(requestNonce, basicOCSPResponse.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce))

        val ocspCertificates = basicOCSPResponse.certs
        log.info("Certificates in response: " + ocspCertificates.size)

        verifyOCSPCerts(basicOCSPResponse, ocspCertificates, ocspResponderCertificate)
        val certstat = basicOCSPResponse.responses
        return getCertificateStatusFromResponse(basicOCSPResponse, certificate, certstat)
    }

    private fun verifyNonce(requestNonce: Extension, responseNonce: Extension) {
        if (requestNonce != responseNonce) {
            throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, "OCSP response nonce failed to validate")
        }
    }

    private fun getCertificateStatusFromResponse(bresp: BasicOCSPResp, certificate: X509Certificate, certstat: Array<SingleResp>
    ): SertifikatInfo {
        if (certstat.size != 1) {
            throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, "OCSP response included wrong number of status, expected one")
        }
        val sr = certstat[0]
        var ssn = getSsn(sr)
        if ("" == ssn) {
            ssn = getSsn(bresp)
        }

        return createSertifikatInfoFromOCSPResponse(certificate, sr, ssn)
    }

    private fun getSsn(sr: SingleResp): String {
        return getSsn(sr.getExtension(SSN_POLICY_ID))
    }

    private fun getSsn(bresp: BasicOCSPResp): String {
        return getSsn(bresp.getExtension(SSN_POLICY_ID))
    }

    private fun getSsn(ssnExtension: Extension?): String {
        return if (ssnExtension != null) {
            try {
                String(ssnExtension.extnValue.encoded).replace(Regex("\\D"), "")
            } catch (e: IOException) {
                throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to extract SSN", e)
            }
        } else ""
    }

    private fun checkOCSPResponseStatus(responseStatus: Int) {
        when (responseStatus) {
            OCSPResponseStatus.UNAUTHORIZED -> throw SertifikatError(
                HttpStatus.INTERNAL_SERVER_ERROR, "OCSP request UNAUTHORIZED"
            )
            OCSPResponseStatus.SIG_REQUIRED -> throw SertifikatError(
                HttpStatus.INTERNAL_SERVER_ERROR, "OCSP request SIG_REQUIRED"
            )
            OCSPResponseStatus.TRY_LATER -> throw SertifikatError(
                HttpStatus.INTERNAL_SERVER_ERROR, "OCSP request TRY_LATER"
            )
            OCSPResponseStatus.INTERNAL_ERROR -> throw SertifikatError(
                HttpStatus.INTERNAL_SERVER_ERROR, "OCSP request INTERNAL_ERROR"
            )
            OCSPResponseStatus.MALFORMED_REQUEST -> throw SertifikatError(
                HttpStatus.INTERNAL_SERVER_ERROR, "OCSP request MALFORMED_REQUEST"
            )
            OCSPResponseStatus.SUCCESSFUL -> log.info("OCSP Request successful")
        }
    }

    private fun verifyOCSPCerts(basicOCSPResponse: BasicOCSPResp, certificates: Array<X509CertificateHolder>, ocspResponderCertificate: X509Certificate) {
        val contentVerifierProviderBuilder = JcaContentVerifierProviderBuilder()
        try {
            if (certificates.isEmpty()) {
                if (!basicOCSPResponse.isSignatureValid(contentVerifierProviderBuilder.build(ocspResponderCertificate))) {
                    throw  ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "OCSP response failed to verify")
                }
            } else {
                val cert = certificates[0]
                verifyProvider(cert, X500Name(ocspResponderCertificate.subjectX500Principal.name))
                log.info("Verifying certificate " + cert.subject.toString())
                if (!basicOCSPResponse.isSignatureValid(contentVerifierProviderBuilder.build(cert))) {
                    log.error("OCSP response failed to verify")
                    throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, "OCSP response failed to verify")
                }
            }
        } catch (e: Exception) {
            log.error("OCSP response validation failed", e)
            throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, "OCSP response validation failed", e)
        }
    }

    private fun verifyProvider(cert: X509CertificateHolder, provider: X500Name) {
        if (!RFC4519Style.INSTANCE.areEqual(provider, cert.issuer)) {
            throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, "OCSP response received from unexpected provider: ${cert.issuer}")
        }
    }

    private fun getOCSPResp(response: ByteArray): OCSPResp {
        return try {
            OCSPResp(response)
        } catch (e: IOException) {
            throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, OCSP_SIGNATURE_VERIFICATION_FAILED, e)
        }
    }

    private fun getBasicOCSPResp(ocspresp: OCSPResp): BasicOCSPResp {
        return try {
            ocspresp.responseObject as BasicOCSPResp
        } catch (e: OCSPException) {
            throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, OCSP_SIGNATURE_VERIFICATION_FAILED, e)
        }
    }

    private fun getOCSPUrl(certificate: X509Certificate): String {
        val url = getAuthorityInfoAccess(certificate, ACCESS_IDENTIFIER_OCSP)
        log.info("OCSP URL: $url")
        return url
    }

    private fun postOCSPRequest(url: String, encoded: ByteArray): OCSPResp {
        val response = try {
            webClient.postForEntity(url, encoded, ByteArray::class.java)
        } catch (e: Exception) {
            log.error("OCSP feilet ${e.localizedMessage}", e)
            throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, OCSP_VERIFICATION_UKJENT_FEIL)
        }
        return getOCSPResp(response.body ?: throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, OCSP_VERIFICATION_EMPTY_RESPONSE) )
    }

    private fun createOCSPRequest(certificate: X509Certificate, ocspResponderCertificate: X509Certificate): OCSPReq {
        try {
            log.debug("Sjekker sertifikat ${certificate.serialNumber}")
            val ocspReqBuilder = OCSPReqBuilder()
            val providerName = ocspResponderCertificate.subjectX500Principal.name
            val provider = X500Name(providerName)
            val signerAlias = KeyStoreHandler.getSignerAlias(providerName)
            val signerCert = KeyStoreHandler.getSignerCert(signerAlias)
            val requestorName = signerCert.subjectX500Principal.name

            val digCalcProv = JcaDigestCalculatorProviderBuilder().setProvider(bcProvider).build()
            val id: CertificateID = JcaCertificateID(
                digCalcProv.get(CertificateID.HASH_SHA1),
                ocspResponderCertificate,
                certificate.serialNumber
            )
            ocspReqBuilder.addRequest(id)
            val extensionsGenerator = ExtensionsGenerator()

            addServiceLocator(certificate, extensionsGenerator, provider)
            addSsnExtension(certificate, extensionsGenerator)
            addNonceExtension(extensionsGenerator)

            ocspReqBuilder.setRequestExtensions(extensionsGenerator.generate())

            ocspReqBuilder.setRequestorName(GeneralName(GeneralName.directoryName, requestorName))
            val request: OCSPReq = ocspReqBuilder.build(
                JcaContentSignerBuilder("SHA256WITHRSAENCRYPTION").setProvider(bcProvider)
                    .build(KeyStoreHandler.getSignerKey(signerAlias)),
                KeyStoreHandler.getCertificateChain(signerAlias)
            )
            log.debug("OCSP Request created")
            log.debug("Request signed: ${request.isSigned}")
            return request
        } catch (e: Exception) {
            log.error("${certificate.serialNumber} $FAILED_TO_GENERATE_REVOCATION_REQUEST")
            throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, FAILED_TO_GENERATE_REVOCATION_REQUEST, e)
        }
    }

    private fun getOcspResponderCertificate(certificateIssuer: String): X509Certificate {
        log.debug("getOcspResponderCertificate: $certificateIssuer")
        KeyStoreHandler.trustStore.aliases().toList().forEach { alias ->
            val cert = KeyStoreHandler.trustStore.getCertificate(alias) as X509Certificate
            if (cert.subjectX500Principal.name == certificateIssuer) {
                return cert
            }
        }
        log.warn("Fant ikke issuer sertifikat for '$certificateIssuer', kan ikke gjøre OCSP-spørringer mot denne CAen")
        throw SertifikatError(HttpStatus.BAD_REQUEST, "Fant ikke issuer sertifikat for '$certificateIssuer'", false)
    }

    private fun addNonceExtension(extensionsGenerator: ExtensionsGenerator) {
        val nonce = BigInteger.valueOf(System.currentTimeMillis())
        extensionsGenerator.addExtension(
            OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
            false,
            DEROctetString(nonce.toByteArray())
        )
    }

    private fun addServiceLocator(certificate: X509Certificate, extensionsGenerator: ExtensionsGenerator, provider: X500Name) {
        getAuthorityInfoAccessObject(certificate)?.let {
            val vector = ASN1EncodableVector()
            vector.add(it.toASN1Primitive())
            vector.add(provider)
            extensionsGenerator.addExtension(
                OCSPObjectIdentifiers.id_pkix_ocsp_service_locator,
                false,
                DEROctetString(DERSequence(vector))
            )
        }
    }

    private fun addSsnExtension(certificate: X509Certificate, extensionsGenerator: ExtensionsGenerator) {
        if (!isVirksomhetssertifikat(certificate)) {
            log.info("adding SSN extension")
            extensionsGenerator.addExtension(SSN_POLICY_ID, false, DEROctetString(byteArrayOf(0)))
        }
    }
}