// The classes every agent line carries: compiled once, for Java 8, so each agent JAR holds the same
// bytecode for them. The launcher (io.ohmyrasp.agent.launch.AgentLauncher) lives here too: it is the
// entry of every agent JAR and must load on any Java version a JAR can be attached to.
plugins {
    `java-library`
}

dependencies {
    // Hook visitors extend ASM types; the agent JARs relocate ASM into io.ohmyrasp.agent.shaded.asm.
    api("org.ow2.asm:asm:9.11.1")
    api("org.ow2.asm:asm-commons:9.11.1")

    // JUnit 5: JUnit 6 needs Java 17, and these tests compile at release 8 like the code they test.
    testImplementation("org.junit.jupiter:junit-jupiter:5.14.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.14.4")
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(8)
}

tasks.jar {
    archiveBaseName.set("ohmyrasp-agent-shared")
}
