FROM gradle:jdk25 AS build
WORKDIR /workspace
COPY --chown=gradle:gradle . .
RUN gradle --no-daemon clean test agent:agentJar playground:war

FROM tomcat:jdk25
RUN rm -rf /usr/local/tomcat/webapps/*
COPY --from=build /workspace/playground/build/libs/playground.war /usr/local/tomcat/webapps/ROOT.war
COPY --from=build /workspace/agent/build/libs/ohmyrasp-agent.jar /opt/ohmyrasp/ohmyrasp-agent.jar
RUN mkdir -p /opt/ohmyrasp/logs && chmod -R 777 /opt/ohmyrasp
ENV OHMYRASP_LOG=/opt/ohmyrasp/logs/events.jsonl
ENV UMASK=0000
