import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
import java.util.zip.ZipFile

plugins {
    java
    id("com.gradleup.shadow")
}

dependencies {
    implementation("org.ow2.asm:asm:9.7.1")
    implementation("org.ow2.asm:asm-commons:9.7.1")

    testImplementation("com.alibaba:fastjson:2.0.62")
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
    options.release.set(8)
}

tasks.jar {
    archiveBaseName.set("ohmyrasp-agent-java8-thin")
}

val agentJava8Jar by tasks.registering(ShadowJar::class) {
    group = "build"
    description = "Builds the dedicated Java 8 era agent jar."
    archiveBaseName.set("ohmyrasp-agent-java8")
    archiveClassifier.set("")
    archiveVersion.set("")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    configurations = listOf(project.configurations.runtimeClasspath.get())

    manifest {
        attributes(
            "Premain-Class" to "io.ohmyrasp.agent.java8.OhMyRaspJava8Agent",
            "Agent-Class" to "io.ohmyrasp.agent.java8.OhMyRaspJava8Agent",
            "Boot-Class-Path" to "ohmyrasp-agent-java8.jar",
            "Can-Redefine-Classes" to "true",
            "Can-Retransform-Classes" to "true",
            "Implementation-Title" to "OhMyRasp Java 8 Era Agent"
        )
    }

    from(sourceSets.main.get().output)
    relocate("org.objectweb.asm", "io.ohmyrasp.agent.shaded.asm")
    exclude("**/module-info.class", "META-INF/versions/**")
}

val verifyJava8AgentBytecode by tasks.registering {
    group = "verification"
    description = "Verifies the Java 8 era agent jar emits Java 8 class files."
    dependsOn(agentJava8Jar)

    doLast {
        val jarFile = agentJava8Jar.get().archiveFile.get().asFile
        ZipFile(jarFile).use { zip ->
            val classEntries = zip.entries().asSequence()
                .filter { !it.isDirectory && it.name.endsWith(".class") }
                .toList()
            require(classEntries.isNotEmpty()) {
                "No Java 8 era agent classes were packaged."
            }
            classEntries.forEach { entry ->
                zip.getInputStream(entry).use { input ->
                    val header = ByteArray(8)
                    val read = input.read(header)
                    require(read == 8) {
                        "Could not read class header from ${entry.name}"
                    }
                    val major = ((header[6].toInt() and 0xff) shl 8) or (header[7].toInt() and 0xff)
                    require(major <= 52) {
                        "Expected Java 8-compatible classfile major <= 52, got $major for ${entry.name}"
                    }
                }
            }
        }
    }
}

tasks.assemble {
    dependsOn(agentJava8Jar)
}

tasks.check {
    dependsOn(verifyJava8AgentBytecode)
}
