ARG TOMCAT_IMAGE=tomcat:11.0-jdk25

FROM gradle:jdk25 AS build
ARG PLAYGROUND_WAR=playground/build/libs/playground.war
WORKDIR /workspace
COPY --chown=gradle:gradle . .
RUN gradle --no-daemon clean test agent:agentJar playground:war playground-javax:war
RUN mkdir -p /workspace/build/selected && cp "/workspace/${PLAYGROUND_WAR}" /workspace/build/selected/playground.war

FROM ${TOMCAT_IMAGE}
RUN rm -rf /usr/local/tomcat/webapps/*
COPY --from=build /workspace/build/selected/playground.war /usr/local/tomcat/webapps/ROOT.war
COPY --from=build /workspace/agent/build/libs/ohmyrasp-agent.jar /opt/ohmyrasp/ohmyrasp-agent.jar
RUN mkdir -p /opt/ohmyrasp/logs && chmod -R 777 /opt/ohmyrasp
ENV OHMYRASP_LOG=/opt/ohmyrasp/logs/events.jsonl
ENV UMASK=0000
