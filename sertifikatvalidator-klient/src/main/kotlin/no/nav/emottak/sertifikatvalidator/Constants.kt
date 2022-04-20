package no.nav.emottak.sertifikatvalidator

const val FEIL_X509CERTIFICATE = "Kunne ikke lese X509Certificate"
const val FEIL_BASE64_X509CERTIFICATE = "Kunne ikke lese base64 encoded X509Certificate"
const val SERTIFIKAT_VALIDERING_OK = "Sertifikatvalidering fullført"
const val SERTIFIKAT_VALIDERING_FEILET = "Sertifikatvalidering feilet av ukjent grunn"
const val SERTIFIKAT_REVOKERT = "Sertifikat revokert"
const val SERTIFIKAT_IKKE_REVOKERT = "Sertifikat ikke revokert"
const val SERTIFIKAT_IKKE_GYLDIG = "Sertifikat ikke gyldig i angitt tidsrom"
const val SERTIFIKAT_IKKE_GYLDIG_LENGER = "Sertifikat utløpt"
const val SERTIFIKAT_IKKE_GYLDIG_ENDA = "Sertifikat ikke gyldig enda"
const val SERTIFIKAT_SELF_SIGNED = "Sertifikat er selvsignert"

const val FAILED_TO_GENERATE_REVOCATION_REQUEST = "Feil ved opprettelse av OCSP request"
const val OCSP_SIGNATURE_VERIFICATION_FAILED = "Feil ved opprettelse av OCSP respons"
const val OCSP_VERIFICATION_UKJENT_FEIL = "Ukjent feil ved OCSP spørring. Kanskje OCSP endepunktet er nede?"
const val OCSP_VERIFICATION_EMPTY_RESPONSE = "Ukjent feil ved OCSP spørring. Kanskje OCSP endepunktet er nede?"
const val ALL_REVOCATION_CHECKS_DISABLED = "OCSP og CRL sjekker deaktivert, dette skal ikke være mulig"

const val FAILED_TO_CREATE_CRL = "Henting av CRL feilet"
const val REVOCATION_REASON_UNKNOWN = "Ukjent grunn"
const val CERTIFICATE_ISSUER_UNKNOWN = "Ukjent sertifikatutsteder"

const val REVOKASJON_STATUS_FEILET = "Kan ikke fastslå revokasjonsstatus, kan være revokert"
const val REVOKASJON_STATUS_UKJENT = "Revokasjonstatus ukjent, kan være revokert"
const val REVOKASJON_STATUS_MANGLER = "Revokasjonstatus mangler, kan være revokert"

const val UKJENT_FEIL = "Ukjent feil"

const val SERVICE_URL_PROD =
    "https://emottak-sertifikatvalidator.intern.nav.no/api//valider/sertifikat"
const val SERVICE_URL_DEV =
    "https://emottak-sertifikatvalidator.dev.intern.nav.no/api/valider/sertifikat"

const val BACKEND_CLUSTER_NAME = "dev-fss"
const val BACKEND_NAMESPACE = "team-emottak"
const val BACKEND_APPLICATION_NAME = "emottak-sertifikatvalidator"
