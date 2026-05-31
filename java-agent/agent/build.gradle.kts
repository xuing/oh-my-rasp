plugins {
    java
}

dependencies {
    implementation("org.ow2.asm:asm:latest.release")
    implementation("org.ow2.asm:asm-commons:latest.release")

    testImplementation("org.junit.jupiter:junit-jupiter:latest.release")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:latest.release")
}

tasks.jar {
    archiveBaseName.set("ohmyrasp-agent-thin")
}

val agentJar by tasks.registering(Jar::class) {
    group = "build"
    description = "Builds the self-contained Java agent jar."
    archiveBaseName.set("ohmyrasp-agent")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE

    manifest {
        attributes(
            "Premain-Class" to "io.ohmyrasp.agent.OhMyRaspAgent",
            "Agent-Class" to "io.ohmyrasp.agent.OhMyRaspAgent",
            "Can-Redefine-Classes" to "true",
            "Can-Retransform-Classes" to "true",
            "Implementation-Title" to "OhMyRasp Java Agent"
        )
    }

    from(sourceSets.main.get().output)
    from({
        configurations.runtimeClasspath.get()
            .filter { it.name.endsWith(".jar") }
            .map { zipTree(it) }
    })
}

tasks.assemble {
    dependsOn(agentJar)
}
