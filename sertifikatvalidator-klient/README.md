# emottak-sertifikatvalidator-klient
Klientimplementasjon for å snakke med signaturverifikasjonstjenesten

## Hvordan ta i bruk

### Legg til repository (eksempel for maven)
```xml
    <repositories>
        ...
        <repository>
            <id>github</id>
            <url>https://maven.pkg.github.com/navikt/emottak-sertifikatvalidator</url>
        </repository>
        ...
    </repositories>
```

### Legg til dependency (eksempel for maven):
Nyeste versjon av [klientbiblioteket](https://github.com/navikt/emottak-sertifikatvalidator/packages/1232556).
```xml
<dependency>
  <groupId>no.nav.emottak</groupId>
  <artifactId>sertifikatvalidator-klient</artifactId>
  <version>0.1.0</version>
</dependency>
```

### Validere et sertifikat (eksempel for java):
```Java
import no.nav.emottak.klient.Sertifikatvalidator;
import no.nav.emottak.sertifikatvalidator.common.model.SertifikatInfo;

Sertifikatvalidator sertifikatvalidator = new Sertifikatvalidator();
SertifikatInfo sertifikatInfo = sertifikatvalidator.valider(sertifikat);

```

