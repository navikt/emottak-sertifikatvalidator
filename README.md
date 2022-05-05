[![Build and deploy emottak-sertifikatvalidator](https://github.com/navikt/emottak-sertifikatvalidator/actions/workflows/main.yaml/badge.svg?branch=master)](https://github.com/navikt/emottak-sertifikatvalidator/actions/workflows/main.yaml)

# emottak-sertifikatvalidator
Tjeneste for å validere sertifikater utstedt av Buypass og Commfides.
Tjenesten er delt i to komponenter, en server med REST-endepunkt, samt en klientimplementasjon som wrapper 
REST-tjenestene i et bibliotek man kan bruke som en dependency ved behov.

### Server
Tjenestene for verifikasjon av signaturer finnes i [dev](https://emottak-sertifikatvalidator.dev.intern.nav.no/internal/swagger-ui/index.html)
og [prod](https://emottak-sertifikatvalidator.intern.nav.no/internal/swagger-ui/index.html)

### Klient
For detaljer rundt bruk av klientbiblioteket, les [klient-readme](sertifikatvalidator-klient/README.md).
 

## Technologies used
* Kotlin
* Spring Boot
* Maven

#### Requirements


#### Build and run tests
`mvn clean install`

#### Creating a docker image
`docker build -t emottak-sertifikatvalidator .`

#### Running a docker image
`docker run --rm -it -p 8080:8080 emottak-sertifikatvalidator`

