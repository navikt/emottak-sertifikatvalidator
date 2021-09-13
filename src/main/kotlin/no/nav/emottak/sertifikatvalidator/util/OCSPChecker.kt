package no.nav.emottak.sertifikatvalidator.util

import no.nav.emottak.sertifikatvalidator.FAILED_TO_GENERATE_REVOCATION_REQUEST
import no.nav.emottak.sertifikatvalidator.OCSP_SIGNATURE_VERIFICATION_FAILED
import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.SertifikatInfo
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
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.server.ResponseStatusException
import reactor.core.publisher.Mono
import java.io.IOException
import java.math.BigInteger
import java.security.PrivateKey
import java.security.cert.X509Certificate

class OCSPChecker {
    companion object {
        private val ACCESS_IDENTIFIER_OCSP = ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1")
        private val ssnPolicyId = ASN1ObjectIdentifier("2.16.578.1.16.3.2")
        private val signerAlias = "nav_test4ca3_nonrep"
        private val responderAlias = "buypass_test4_ca1"
        private val bcProvider = BouncyCastleProvider()

        private val ocspResponderCertificate = KeyStoreHandler.trustStore.getCertificate(responderAlias) as X509Certificate
        private val providerName = ocspResponderCertificate.subjectX500Principal.name
        private val provider = X500Name(providerName)
        private val signerKey = KeyStoreHandler.keyStore.getKey(signerAlias, "123456789".toCharArray()) as PrivateKey
        private val signerCert = KeyStoreHandler.keyStore.getCertificate(signerAlias) as X509Certificate
        private val requestorName = signerCert.subjectX500Principal.name
        private val certificateChain = getCertificateChain(signerAlias)

        fun getOCSPStatus(certificate: X509Certificate): SertifikatInfo? {
            return try {
                val request: OCSPReq = getOCSPRequest(certificate)
                val response = postOCSPRequest(getOCSPUrl(certificate), request.getEncoded())
                decodeResponse(response, certificate, request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce))
            } catch (e: Exception) {
                log.error(e.localizedMessage, e)
                throw ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "error", e)
            }
        }

        private fun decodeResponse(response: OCSPResp, certificate: X509Certificate, requestNonce: Extension): SertifikatInfo {

            checkOCSPResponseStatus(response.status)

            val basicOCSPResponse: BasicOCSPResp = getBasicOCSPResp(response)

            verifyNonce(requestNonce, basicOCSPResponse.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce))

            val ocspCertificates = basicOCSPResponse.certs
            log.info("Certificates in response: " + ocspCertificates.size)

            verifyOCSPCerts(basicOCSPResponse, ocspCertificates)
            val certstat = basicOCSPResponse.responses
            return getCertificateStatusFromResponse(basicOCSPResponse, certificate, certstat)
        }

        private fun verifyNonce(requestNonce: Extension, responseNonce: Extension) {
            if (requestNonce != responseNonce) {
                throw ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "OCSP response nonce failed to validate")
            }
        }

        private fun getCertificateStatusFromResponse(bresp: BasicOCSPResp, certificate: X509Certificate, certstat: Array<SingleResp>
        ): SertifikatInfo {
            if (certstat.size != 1) {
                throw ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "OCSP response included wrong number of status, expected one")
            }
            val sr = certstat[0]
            var ssn = getSsn(sr)
            if ("" == ssn) {
                ssn = getSsn(bresp)
            }

            return createSertifikatInfoFromOCSPResponse(certificate, sr, ssn)
        }

        private fun getSsn(sr: SingleResp): String {
            return getSsn(sr.getExtension(ssnPolicyId))
        }

        private fun getSsn(bresp: BasicOCSPResp): String {
            return getSsn(bresp.getExtension(ssnPolicyId))
        }

        private fun getSsn(ssnExtension: Extension?): String {
            return if (ssnExtension != null) {
                try {
                    ssnExtension.extnValue.encoded.toString()
                } catch (e: IOException) {
                    throw ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to extract SSN")
                }
            } else ""
        }

        private fun checkOCSPResponseStatus(responseStatus: Int) {
            when (responseStatus) {
                OCSPResponseStatus.UNAUTHORIZED -> throw ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR, "OCSP request UNAUTHORIZED"
                )
                OCSPResponseStatus.SIG_REQUIRED -> throw ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR, "OCSP request SIG_REQUIRED"
                )
                OCSPResponseStatus.TRY_LATER -> throw ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR, "OCSP request TRY_LATER"
                )
                OCSPResponseStatus.INTERNAL_ERROR -> throw ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR, "OCSP request INTERNAL_ERROR"
                )
                OCSPResponseStatus.MALFORMED_REQUEST -> throw ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR, "OCSP request MALFORMED_REQUEST"
                )
                OCSPResponseStatus.SUCCESSFUL -> log.info("OCSP Request successful")
            }
        }

        private fun verifyOCSPCerts(basicOCSPResponse: BasicOCSPResp, certificates: Array<X509CertificateHolder>) {
            val contentVerifierProviderBuilder = JcaContentVerifierProviderBuilder()
            try {
                if (certificates.isEmpty()) {
                    if (!basicOCSPResponse.isSignatureValid(contentVerifierProviderBuilder.build(ocspResponderCertificate))) {
                        throw  ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "OCSP response failed to verify")
                    }
                } else {
                    val cert = certificates[0]
                    verifyProvider(cert)
                    log.info("Verifying certificate " + cert.subject.toString())
                    if (!basicOCSPResponse.isSignatureValid(contentVerifierProviderBuilder.build(cert))) {
                        log.error("OCSP response failed to verify")
                        throw ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "OCSP response failed to verify")
                    }
                }
            } catch (e: Exception) {
                log.error("OCSP response validation failed", e)
                throw ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "OCSP response validation failed", e)
            }
        }

        private fun verifyProvider(cert: X509CertificateHolder) {
            if (!RFC4519Style.INSTANCE.areEqual(provider, cert.issuer)) {
                throw ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "OCSP response received from unexpected provider: ${cert.issuer}")
            }
        }

        private fun getOCSPResp(response: ByteArray): OCSPResp {
            return try {
                OCSPResp(response)
            } catch (e: IOException) {
                throw ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, OCSP_SIGNATURE_VERIFICATION_FAILED, e)
            }
        }

        private fun getBasicOCSPResp(ocspresp: OCSPResp): BasicOCSPResp {
            return try {
                ocspresp.responseObject as BasicOCSPResp
            } catch (e: OCSPException) {
                throw ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, OCSP_SIGNATURE_VERIFICATION_FAILED, e)
            }
        }

        private fun getOCSPUrl(certificate: X509Certificate): String {
            val url = getAuthorityInfoAccess(certificate, ACCESS_IDENTIFIER_OCSP)
            log.info("OCSP URL: $url")
            return url //"http://ocsp.test4.buypass.no/ocsp/BPClass3T4CA3"
        }

        private fun postOCSPRequest(url: String, encoded: ByteArray): OCSPResp {
            val webClient: WebClient = WebClient.create(url)
            val response = webClient
                .post()
                .body(Mono.just(encoded), ByteArray::class.java)
                .accept(MediaType.APPLICATION_OCTET_STREAM)
                .retrieve()
                .bodyToFlux(ByteArray::class.java)
                .blockFirst()
                ?: throw ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Timeout")
            return getOCSPResp(response)
        }

        private fun getOCSPRequest(certificate: X509Certificate): OCSPReq {
            try {
                log.debug("Sjekker sertifikat ${certificate.serialNumber}")
                val ocspReqBuilder = OCSPReqBuilder()
                val digCalcProv = JcaDigestCalculatorProviderBuilder().setProvider(bcProvider).build()
                val id: CertificateID = JcaCertificateID(
                    digCalcProv.get(CertificateID.HASH_SHA1),
                    ocspResponderCertificate,
                    certificate.serialNumber
                )
                ocspReqBuilder.addRequest(id)
                val extensionsGenerator = ExtensionsGenerator()

                addServiceLocator(certificate, extensionsGenerator)
                addSsnExtension(certificate, extensionsGenerator)
                addNonceExtension(extensionsGenerator)

                ocspReqBuilder.setRequestExtensions(extensionsGenerator.generate())

                ocspReqBuilder.setRequestorName(GeneralName(GeneralName.directoryName, requestorName))
                val request: OCSPReq = ocspReqBuilder.build(
                    JcaContentSignerBuilder("SHA256WITHRSAENCRYPTION").setProvider(bcProvider)
                        .build(signerKey), certificateChain
                )
                log.debug("OCSP Request created")
                log.debug("Request signed: ${request.isSigned}")
                return request
            } catch (e: Exception) {
                log.error(FAILED_TO_GENERATE_REVOCATION_REQUEST, e)
                throw ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, FAILED_TO_GENERATE_REVOCATION_REQUEST, e)
            }
        }

        private fun addNonceExtension(extensionsGenerator: ExtensionsGenerator) {
            val nonce = BigInteger.valueOf(System.currentTimeMillis())
            extensionsGenerator.addExtension(
                OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                false,
                DEROctetString(nonce.toByteArray())
            )
        }

        private fun addServiceLocator(certificate: X509Certificate, extensionsGenerator: ExtensionsGenerator) {
            getAuthorityInfoAccessObject(certificate)?.let {
                val vector = ASN1EncodableVector()
                vector.add(it.toASN1Primitive())
                vector.add(X500Name(providerName))
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
                extensionsGenerator.addExtension(ssnPolicyId, false, DEROctetString(byteArrayOf(0)))
            }
        }
    }
}