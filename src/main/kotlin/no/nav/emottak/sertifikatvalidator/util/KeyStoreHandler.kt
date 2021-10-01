package no.nav.emottak.sertifikatvalidator.util

import no.nav.emottak.sertifikatvalidator.log
import no.nav.emottak.sertifikatvalidator.model.SertifikatError
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStrictStyle
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x500.style.RFC4519Style
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder
import org.springframework.http.HttpStatus
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.naming.ldap.LdapName

class KeyStoreHandler {

    companion object {
        private const val KEYSTORE_TYPE = "JKS"
        private const val TRUSTSTORE_TYPE = "JKS"

        private val signerSubjectDN = getEnvVar("SIGNER_SUBJECT_DN", "SERIALNUMBER=889640782, CN=ARBEIDS- OG VELFERDSETATEN, O=ARBEIDS- OG VELFERDSETATEN, C=NO")

        //private val truststorePath = getEnvVar("TRUSTSTORE_PATH", "classpath:/truststore.jks")
        private val truststorePath = getEnvVar("TRUSTSTORE_PATH")
        private val truststorePwd = getFileAsString(getEnvVar("TRUSTSTORE_PWD"))

        //private val keystorePath = getEnvVar("KEYSTORE_PATH", "classpath:/keystore.jks")
        private val keystorePath = getEnvVar("KEYSTORE_PATH")
        private val keystorePwd = getFileAsString(getEnvVar("KEYSTORE_PWD"))

        val keyStore: KeyStore
        val trustStore: KeyStore

        init {
            keyStore = createKeyStore()
            trustStore = createTrustStore()
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
                val x500Issuer = X500Name(issuerDN)
                val x500IssuerPrincial = X500Name(cert.issuerX500Principal.name)
                val x500signer = X500Name(signerSubjectDN)
                x500signer.rdNs.forEach {
                    log.info("RDN: ${it.first.type}: ${it.first.value}")
                }
                val x500subject = X500Name(cert.subjectX500Principal.name)
                x500subject.rdNs.forEach {
                    log.info("RDN: ${it.first.type}: ${it.first.value}")
                }
                log.info("$alias cert details")
                log.info("$issuerDN")
                log.info("${cert.issuerX500Principal.name}")
                log.info("LDAPNAM: ${LdapName(issuerDN) == LdapName(cert.issuerX500Principal.name)}")
                log.info("RFC4519: ${RFC4519Style.INSTANCE.areEqual(X500Name(issuerDN), X500Name(cert.issuerX500Principal.name))}")
                log.info("BCSTYLE: ${BCStyle.INSTANCE.areEqual(X500Name(issuerDN), X500Name(cert.issuerX500Principal.name))}")
                log.info("BCSTRIC: ${BCStrictStyle.INSTANCE.areEqual(X500Name(issuerDN), X500Name(cert.issuerX500Principal.name))}")
                log.info("${cert.subjectX500Principal.name}")
                log.info("$signerSubjectDN")
                log.info("LDAPNAM: ${LdapName(signerSubjectDN) == LdapName(cert.subjectX500Principal.name)}")
                log.info("RFC4519: ${RFC4519Style.INSTANCE.areEqual(X500Name(signerSubjectDN), X500Name(cert.subjectX500Principal.name))}")
                log.info("BCSTYLE: ${BCStyle.INSTANCE.areEqual(X500Name(signerSubjectDN), X500Name(cert.subjectX500Principal.name))}")
                log.info("BCSTRIC: ${BCStrictStyle.INSTANCE.areEqual(X500Name(signerSubjectDN), X500Name(cert.subjectX500Principal.name))}")
                if (RFC4519Style.INSTANCE.areEqual(X500Name(issuerDN), X500Name(cert.issuerX500Principal.name)) &&
                    RFC4519Style.INSTANCE.areEqual(X500Name(signerSubjectDN), X500Name(cert.subjectX500Principal.name))) {
                    log.info("Found signer certificate for $issuerDN ($alias)")
                    return alias
                }
            }
            throw SertifikatError(HttpStatus.INTERNAL_SERVER_ERROR, "Fant ikke sertifikat for signering for issuer DN: $issuerDN")
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
    }
}