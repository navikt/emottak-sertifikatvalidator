package no.nav.emottak.sertifikatvalidator.util

import java.security.KeyStore

class KeyStoreHandler {

    companion object {
        private const val KEYSTORE_TYPE = "JKS"
        private val truststorePath = getEnvVar("TRUSTSTORE_PATH")
        private val truststorePwd = getEnvVar("TRUSTSTORE_PWD")

        private val keystorePath = getEnvVar("KEYSTORE_PATH")
        private val keystorePwd = getEnvVar("KEYSTORE_PWD")

        val keyStore: KeyStore
        val trustStore: KeyStore

        init {
            keyStore = createKeyStore()
            trustStore = createTrustStore()
        }

        private fun createTrustStore(): KeyStore {
            //return createKeyStoreInstance(truststorePath, truststorePwd)
            return createKeyStoreInstance(truststorePath, getFileAsString(truststorePwd))
        }

        private fun createKeyStore(): KeyStore {
            //return createKeyStoreInstance(keystorePath, keystorePwd)
            return createKeyStoreInstance(keystorePath, getFileAsString(keystorePwd))
        }

        private fun createKeyStoreInstance(storePath: String, storePwd: String): KeyStore {
            val store = KeyStore.getInstance(KEYSTORE_TYPE)
            val inputStream = createInputstreamFromFileName(storePath)
            store.load(inputStream, storePwd.toCharArray())
            return store
        }
    }
}