FROM openjdk:8 as build

ENV GRADLE_VERSION 6.8.3
RUN wget -q https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip \
    && unzip gradle-${GRADLE_VERSION}-bin.zip -d /opt \
    && rm gradle-${GRADLE_VERSION}-bin.zip

COPY . /src

WORKDIR /src
RUN /opt/gradle-${GRADLE_VERSION}/bin/gradle build jar

FROM openmicroscopy/omero-server:latest

ENV ICE_CONFIG /src/ice.config
ENTRYPOINT ["gradle test"]