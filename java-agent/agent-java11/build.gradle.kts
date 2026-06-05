import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
import java.util.zip.ZipFile

plugins {
    java
    id("com.gradleup.shadow")
}

dependencies {
    implementation("org.ow2.asm:asm:9.7.1")
    implementation("org.ow2.asm:asm-commons:9.7.1")

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.10.3")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(25))
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release.set(11)
}

tasks.jar {
    archiveBaseName.set("ohmyrasp-agent-java11-thin")
}

val agentJava11Jar by tasks.registering(ShadowJar::class) {
    group = "build"
    description = "Builds the dedicated Java 11 era agent jar."
    archiveBaseName.set("ohmyrasp-agent-java11")
    archiveClassifier.set("")
    archiveVersion.set("")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    configurations = listOf(project.configurations.runtimeClasspath.get())

    manifest {
        attributes(
            "Premain-Class" to "io.ohmyrasp.agent.java11.OhMyRaspJava11Agent",
            "Agent-Class" to "io.ohmyrasp.agent.java11.OhMyRaspJava11Agent",
            "Can-Redefine-Classes" to "true",
            "Can-Retransform-Classes" to "true",
            "Implementation-Title" to "OhMyRasp Java 11 Era Agent"
        )
    }

    from(sourceSets.main.get().output)
    relocate("org.objectweb.asm", "io.ohmyrasp.agent.shaded.asm")
    exclude("**/module-info.class", "META-INF/versions/**")
}

val verifyJava11AgentBytecode by tasks.registering {
    group = "verification"
    description = "Verifies the Java 11 era agent jar emits Java 11-compatible class files."
    dependsOn(agentJava11Jar)

    doLast {
        val jarFile = agentJava11Jar.get().archiveFile.get().asFile
        ZipFile(jarFile).use { zip ->
            val classEntries = zip.entries().asSequence()
                .filter { !it.isDirectory && it.name.endsWith(".class") }
                .toList()
            require(classEntries.isNotEmpty()) {
                "No Java 11 era agent classes were packaged."
            }
            classEntries.forEach { entry ->
                zip.getInputStream(entry).use { input ->
                    val header = ByteArray(8)
                    val read = input.read(header)
                    require(read == 8) {
                        "Could not read class header from ${entry.name}"
                    }
                    val major = ((header[6].toInt() and 0xff) shl 8) or (header[7].toInt() and 0xff)
                    require(major <= 55) {
                        "Expected Java 11-compatible classfile major <= 55, got $major for ${entry.name}"
                    }
                }
            }
        }
    }
}

tasks.assemble {
    dependsOn(agentJava11Jar)
}

tasks.check {
    dependsOn(verifyJava11AgentBytecode)
}
