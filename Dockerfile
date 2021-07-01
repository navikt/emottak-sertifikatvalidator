FROM navikt/java:16
LABEL maintainer="Team eMottak"

COPY ./target/emottak-sertifikatvalidator-*.jar app.jar

EXPOSE 8080