# Local image for running probes on every agent line: the Gradle builder image
# (JDK 25, Python) plus the other LTS runtimes that lines.toml names.
# java-agent/scripts/check-agent.sh builds it; CI installs each JDK with setup-java instead.
ARG GRADLE_IMAGE
FROM eclipse-temurin:8 AS jdk8
FROM eclipse-temurin:11 AS jdk11
FROM eclipse-temurin:17 AS jdk17
FROM eclipse-temurin:21 AS jdk21
FROM ${GRADLE_IMAGE}
COPY --from=jdk8 /opt/java/openjdk /opt/jdk/8
COPY --from=jdk11 /opt/java/openjdk /opt/jdk/11
COPY --from=jdk17 /opt/java/openjdk /opt/jdk/17
COPY --from=jdk21 /opt/java/openjdk /opt/jdk/21
RUN ln -s /opt/java/openjdk /opt/jdk/25
