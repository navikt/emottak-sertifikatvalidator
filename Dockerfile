FROM navikt/java:16
LABEL maintainer="Team eMottak"

COPY ./sertifikatvalidator-server/target/sertifikatvalidator-server-1.*.jar app.jar

EXPOSE 8080