package no.nav.emottak.sertifikatvalidator.model

import org.springframework.http.HttpStatus
import java.lang.Exception

class SertifikatError : RuntimeException {

    val statusCode: HttpStatus
    val sertifikatInfo: SertifikatInfo?
    val sertifikatData: SertifikatData?
    val logStackTrace: Boolean

    constructor(statusCode: HttpStatus,
                message: String): super(message) {
        this.statusCode = statusCode
        this.sertifikatInfo = null
        this.sertifikatData = null
        this.logStackTrace = true
    }

    constructor(statusCode: HttpStatus,
                message: String,
                logStackTrace: Boolean): super(message) {
        this.statusCode = statusCode
        this.sertifikatInfo = null
        this.sertifikatData = null
        this.logStackTrace = logStackTrace
    }

    constructor(statusCode: HttpStatus,
                message: String,
                sertifikatData: SertifikatData,
                sertifikatInfo: SertifikatInfo
    ): super(message) {
        this.statusCode = statusCode
        this.sertifikatInfo = sertifikatInfo
        this.sertifikatData = sertifikatData
        this.logStackTrace = true
    }

    constructor(statusCode: HttpStatus,
                message: String,
                sertifikatData: SertifikatData,
                sertifikatInfo: SertifikatInfo,
                logStackTrace: Boolean
    ): super(message) {
        this.statusCode = statusCode
        this.sertifikatInfo = sertifikatInfo
        this.sertifikatData = sertifikatData
        this.logStackTrace = logStackTrace
    }

    constructor(statusCode: HttpStatus,
                message: String,
                sertifikatInfo: SertifikatInfo,
                logStackTrace: Boolean
    ): super(message) {
        this.statusCode = statusCode
        this.sertifikatInfo = sertifikatInfo
        this.sertifikatData = null
        this.logStackTrace = logStackTrace
    }

    constructor(statusCode: HttpStatus,
                message: String,
                exception: Exception): super(message, exception) {
        this.statusCode = statusCode
        this.sertifikatInfo = null
        this.sertifikatData = null
        this.logStackTrace = true
    }

    constructor(statusCode: HttpStatus,
                message: String,
                sertifikatData: SertifikatData,
                sertifikatInfo: SertifikatInfo,
                exception: Exception): super(message, exception) {
        this.statusCode = statusCode
        this.sertifikatInfo = sertifikatInfo
        this.sertifikatData = sertifikatData
        this.logStackTrace = true
    }

    constructor(statusCode: HttpStatus,
                message: String,
                sertifikatInfo: SertifikatInfo,
                exception: Exception): super(message, exception) {
        this.statusCode = statusCode
        this.sertifikatInfo = sertifikatInfo
        this.sertifikatData = null
        this.logStackTrace = true
    }

    constructor(statusCode: HttpStatus,
                message: String,
                sertifikatData: SertifikatData,
                exception: Exception): super(message, exception) {
        this.statusCode = statusCode
        this.sertifikatInfo = null
        this.sertifikatData = sertifikatData
        this.logStackTrace = true
    }

    constructor(statusCode: HttpStatus,
                message: String,
                sertifikatData: SertifikatData,
                exception: Exception,
                logStackTrace: Boolean): super(message, exception) {
        this.statusCode = statusCode
        this.sertifikatInfo = null
        this.sertifikatData = sertifikatData
        this.logStackTrace = logStackTrace
    }
}