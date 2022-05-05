package no.nav.emottak.sertifikatvalidator.util

import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.SertifikatError
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.RFC4519Style
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.springframework.http.HttpStatus
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Security
import java.security.cert.X509Certificate

class KeyStoreHandler {

    companion object {
        private const val KEYSTORE_TYPE = "JKS"
        private const val TRUSTSTORE_TYPE = "JKS"

        private val signerSubjectDN = getEnvVar("SIGNER_SUBJECT_DN", "SERIALNUMBER=889640782, CN=ARBEIDS- OG VELFERDSETATEN, O=ARBEIDS- OG VELFERDSETATEN, C=NO")

        private val truststorePath = getEnvVar("TRUSTSTORE_PATH")
        private val truststorePwd = getFileAsString(getEnvVar("TRUSTSTORE_PWD"))

        private val keystorePath = getEnvVar("KEYSTORE_PATH")
        private val keystorePwd = getFileAsString(getEnvVar("KEYSTORE_PWD"))

        val keyStore: KeyStore
        val trustStore: KeyStore

        init {
            keyStore = createKeyStore()
            trustStore = createTrustStore()
            Security.addProvider(BouncyCastleProvider());
        }

        private fun createTrustStore(): KeyStore {
            return createKeyStoreInstance(TRUSTSTORE_TYPE, truststorePath, truststorePwd)
        }

        private fun createKeyStore(): KeyStore {
            return createKeyStoreInstance(KEYSTORE_TYPE, keystorePath, keystorePwd)
        }

        private fun createKeyStoreInstance(keystoreType: String, storePath: String, storePwd: String): KeyStore {
            val store = KeyStore.getInstance(keystoreType)
            val inputStream = createInputstreamFromFileName(storePath)
            store.load(inputStream, storePwd.toCharArray())
            return store
        }

        internal fun getSignerAlias(issuerDN: String): String {
            keyStore.aliases().toList().forEach { alias ->
                val cert = keyStore.getCertificate(alias) as X509Certificate
                if (RFC4519Style.INSTANCE.areEqual(X500Name(issuerDN), X500Name(cert.issuerX500Principal.name)) &&
                    RFC4519Style.INSTANCE.areEqual(X500Name(signerSubjectDN), X500Name(cert.subjectX500Principal.name))) {
                    log.debug("Found signer certificate for $issuerDN ($alias)")
                    return alias
                }
            }
            //TODO
            log.warn("Fant ikke sertifikat for signering for issuer DN: $issuerDN, forsøker med test-alias 'nav_test4ca3_nonrep'")
            return "nav_test4ca3_nonrep"
            //throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, "Fant ikke sertifikat for signering for issuer DN: $issuerDN")
        }

        internal fun getSignerKey(alias: String): PrivateKey {
            return keyStore.getKey(alias, keystorePwd.toCharArray()) as PrivateKey
        }

        internal fun getSignerCert(alias: String): X509Certificate {
            return keyStore.getCertificate(alias) as X509Certificate
        }

        internal fun getCertificateChain(alias: String): Array<X509CertificateHolder> {
            val chain = keyStore.getCertificateChain(alias)
            //val holders = arrayOfNulls<JcaX509CertificateHolder>(chain.size)
            return chain?.filterIsInstance<X509Certificate>()?.map { JcaX509CertificateHolder(it) }?.toTypedArray() ?: emptyArray()
            //    for (i in chain.indices) {
            //        holders[i] = JcaX509CertificateHolder(chain[i])
            //    }
            //    return holders
        }

        internal fun getTrustedRootCerts(): Set<X509Certificate> {
            return getTrustStoreCertificates().filter { isSelfSigned(it) }.toSet()
        }

        internal fun getIntermediateCerts(): Set<X509Certificate> {
            return getTrustStoreCertificates().filter { !isSelfSigned(it) }.toSet()
        }

        private fun getTrustStoreCertificates(): Set<X509Certificate> {
            return trustStore.aliases().toList().map { alias -> trustStore.getCertificate(alias) as X509Certificate }.toSet()
        }
    }
}