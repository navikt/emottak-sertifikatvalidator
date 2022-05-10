FROM navikt/java:16
LABEL maintainer="Team eMottak"

ENV JAVA_OPTS="${JAVA_OPTS} -Dlogging.config=classpath:logback-remote.xml"

COPY ./sertifikatvalidator-server/target/sertifikatvalidator-server-1.*.jar app.jar

EXPOSE 8080