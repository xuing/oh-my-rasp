import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar

plugins {
    java
    id("com.gradleup.shadow")
}

dependencies {
    // ASM 9.8 is the first release whose ClassReader can read Java 25 (class
    // file major version 69). Because this is the JDK 25 agent and it must
    // instrument genuine Java 25 application bytecode at runtime, it must stay
    // >= 9.8 — do NOT downgrade to the 9.7.1 the java8/11/17 backports pin (those
    // only ever see Java <= 17, major <= 61). The version is pinned (not
    // latest.release) for reproducible, supply-chain-reviewable builds.
    implementation("org.ow2.asm:asm:9.8")
    implementation("org.ow2.asm:asm-commons:9.8")

    testImplementation("com.alibaba:fastjson:1.2.83")
    testImplementation("org.junit.jupiter:junit-jupiter:6.1.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.10.3")
}

tasks.jar {
    archiveBaseName.set("ohmyrasp-agent-thin")
}

// The agent jar is appended to the bootstrap classloader at runtime
// (OhMyRaspAgent.appendToBootstrapClassLoaderSearch). If ASM shipped under its
// original org.objectweb.asm package it would shadow the instrumented
// application's own ASM (Spring CGLIB, Hibernate, Byte Buddy, Groovy, …) and
// crash the host app on any version mismatch. Relocating ASM into a private
// package eliminates that conflict. The java8/11/17 backports already do this.
val agentJar by tasks.registering(ShadowJar::class) {
    group = "build"
    description = "Builds the self-contained Java agent jar with ASM relocated."
    archiveBaseName.set("ohmyrasp-agent")
    archiveClassifier.set("")
    archiveVersion.set("")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    configurations = listOf(project.configurations.runtimeClasspath.get())

    manifest {
        attributes(
            "Premain-Class" to "io.ohmyrasp.agent.OhMyRaspAgent",
            "Agent-Class" to "io.ohmyrasp.agent.OhMyRaspAgent",
            "Can-Redefine-Classes" to "true",
            "Can-Retransform-Classes" to "true",
            "Implementation-Title" to "OhMyRasp Java Agent (JDK 25)"
        )
    }

    from(sourceSets.main.get().output)
    relocate("org.objectweb.asm", "io.ohmyrasp.agent.shaded.asm")
    exclude("**/module-info.class")
}

tasks.assemble {
    dependsOn(agentJar)
}
