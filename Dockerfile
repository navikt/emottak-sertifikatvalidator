FROM navikt/java:16
LABEL maintainer="Team eMottak"

COPY ./sertifikatvalidator-server/target/emottak-sertifikatvalidator-1.*.jar app.jar

EXPOSE 8080