#!/bin/sh
# Stage the Gradle build outputs for packaging (the universal package and one per line) and check the JDK 21 download aliases.
set -eu
cd "$(dirname "$0")/../.."

cp java-agent/agent-all/build/libs/ohmyrasp.jar deploy/shirudo/ohmyrasp/

for track in java8 java11 java17 jdk25; do
    cp "java-agent/agent-${track}/build/libs/ohmyrasp-${track}.jar" "deploy/shirudo/ohmyrasp-${track}/"
done

primary=java-agent/agent-jdk25/build
cmp "$primary/libs/ohmyrasp-agent.jar" "$primary/jdk21/ohmyrasp-agent-jdk21.jar"
cmp "$primary/libs/ohmyrasp-jdk25.jar" "$primary/jdk21/ohmyrasp-jdk21.jar"
cp "$primary/jdk21/ohmyrasp-jdk21.jar" deploy/shirudo/ohmyrasp-jdk21/

mkdir -p dist/jdk21
cp "$primary/jdk21/"*.jar dist/jdk21/
tar -chzf dist/jdk21/ohmyrasp-jdk21-shirudo.tar.gz -C deploy/shirudo \
    ohmyrasp-jdk21/Beefile ohmyrasp-jdk21/README.md ohmyrasp-jdk21/build.sh ohmyrasp-jdk21/ohmyrasp-jdk21.jar
