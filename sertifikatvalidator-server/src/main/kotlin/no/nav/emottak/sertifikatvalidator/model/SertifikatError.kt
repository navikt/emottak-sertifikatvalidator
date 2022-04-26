package no.nav.emottak.sertifikatvalidator.model

import org.springframework.http.HttpStatus
import java.lang.Exception
import java.security.cert.X509Certificate

class SertifikatError : RuntimeException {

    val statusCode: HttpStatus
    val sertifikatInfo: SertifikatInfo?
    val certificate: X509Certificate?
    val logStackTrace: Boolean

    constructor(statusCode: HttpStatus,
                message: String): super(message) {
        this.statusCode = statusCode
        this.sertifikatInfo = null
        this.certificate = null
        this.logStackTrace = true
    }

    constructor(statusCode: HttpStatus,
                message: String,
                logStackTrace: Boolean): super(message) {
        this.statusCode = statusCode
        this.sertifikatInfo = null
        this.certificate = null
        this.logStackTrace = logStackTrace
    }

    constructor(statusCode: HttpStatus,
                message: String,
                sertifikatInfo: SertifikatInfo
    ): super(message) {
        this.statusCode = statusCode
        this.sertifikatInfo = sertifikatInfo
        this.certificate = null
        this.logStackTrace = true
    }

    constructor(statusCode: HttpStatus,
                message: String,
                sertifikatInfo: SertifikatInfo,
                logStackTrace: Boolean
    ): super(message) {
        this.statusCode = statusCode
        this.sertifikatInfo = sertifikatInfo
        this.certificate = null
        this.logStackTrace = logStackTrace
    }

    constructor(statusCode: HttpStatus,
                message: String,
                exception: Exception): super(message, exception) {
        this.statusCode = statusCode
        this.sertifikatInfo = null
        this.certificate = null
        this.logStackTrace = true
    }

    constructor(statusCode: HttpStatus,
                message: String,
                sertifikatInfo: SertifikatInfo,
                exception: Exception): super(message, exception) {
        this.statusCode = statusCode
        this.sertifikatInfo = sertifikatInfo
        this.certificate = null
        this.logStackTrace = true
    }

    constructor(statusCode: HttpStatus,
                message: String,
                certificate: X509Certificate,
                exception: Exception): super(message, exception) {
        this.statusCode = statusCode
        this.sertifikatInfo = null
        this.certificate = certificate
        this.logStackTrace = true
    }

    constructor(statusCode: HttpStatus,
                message: String,
                certificate: X509Certificate,
                exception: Exception,
                logStackTrace: Boolean): super(message, exception) {
        this.statusCode = statusCode
        this.sertifikatInfo = null
        this.certificate = certificate
        this.logStackTrace = logStackTrace
    }
}