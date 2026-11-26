import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
import java.io.ByteArrayInputStream
import java.util.Properties
import java.util.jar.Manifest
import java.util.zip.ZipFile

plugins {
    java
    id("com.gradleup.shadow")
}

dependencies {
    implementation(project(":shared"))
    implementation("org.ow2.asm:asm:9.11.1")
    implementation("org.ow2.asm:asm-commons:9.11.1")

    testImplementation("com.alibaba:fastjson:1.2.83")
    testImplementation("org.junit.jupiter:junit-jupiter:5.14.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.14.4")
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

val agentJava11Jar = tasks.register<ShadowJar>("agentJava11Jar") {
    group = "build"
    description = "Builds the dedicated Java 11 era agent jar."
    archiveBaseName.set("ohmyrasp-agent-java11")
    archiveClassifier.set("")
    archiveVersion.set("")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    configurations = listOf(project.configurations.runtimeClasspath.get())

    manifest {
        attributes(
            "Premain-Class" to "io.ohmyrasp.agent.launch.AgentLauncher",
            "Agent-Class" to "io.ohmyrasp.agent.launch.AgentLauncher",
            "Can-Redefine-Classes" to "true",
            "Can-Retransform-Classes" to "true",
            "Implementation-Title" to "OhMyRasp Java 11 Era Agent"
        )
    }

    from(sourceSets.main.get().output)
    relocate("org.objectweb.asm", "io.ohmyrasp.agent.shaded.asm")
    exclude("**/module-info.class", "META-INF/versions/**")
}

val verifyJava11AgentBytecode = tasks.register("verifyJava11AgentBytecode") {
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

val shirudoMode = providers.gradleProperty("shirudoMode")
    .map { it.trim() }
    .orElse("block")
    .get()
    .ifEmpty { "block" }
val shirudoLockConfig = providers.gradleProperty("shirudoLockConfig")
    .map { it.trim() }
    .orElse("true")
    .get()
    .ifEmpty { "true" }
val shirudoConfigDir = layout.buildDirectory.dir("generated/shirudo-config")

val generateShirudoConfig = tasks.register("generateShirudoConfig") {
    group = "build"
    description = "Generates META-INF/ohmyrasp-shirudo.properties for shirudo upatch jars."
    inputs.property("shirudoMode", shirudoMode)
    inputs.property("shirudoLockConfig", shirudoLockConfig)
    outputs.dir(shirudoConfigDir)

    doLast {
        val metaInfDir = shirudoConfigDir.get().asFile.resolve("META-INF")
        metaInfDir.mkdirs()
        metaInfDir.resolve("ohmyrasp-shirudo.properties").writeText(
            buildString {
                appendLine("standalone=true")
                appendLine("lock_config=$shirudoLockConfig")
                appendLine("mode=$shirudoMode")
                appendLine("control=none")
                appendLine("log=stderr")
                appendLine("latency_sample=0")
            },
            Charsets.UTF_8
        )
    }
}

val shirudoUpatchJar = tasks.register<ShadowJar>("shirudoUpatchJar") {
    group = "build"
    description = "Builds the standalone Java 11 shirudo upatch agent jar."
    archiveBaseName.set("ohmyrasp-java11")
    archiveClassifier.set("")
    archiveVersion.set("")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    configurations = listOf(project.configurations.runtimeClasspath.get())
    dependsOn(generateShirudoConfig)

    manifest {
        attributes(
            "Premain-Class" to "io.ohmyrasp.agent.launch.AgentLauncher",
            "Agent-Class" to "io.ohmyrasp.agent.launch.AgentLauncher",
            "Can-Redefine-Classes" to "true",
            "Can-Retransform-Classes" to "true",
            "Implementation-Title" to "OhMyRasp Java 11 Era Agent",
            "OhMyRasp-Shirudo-Upatch" to "true"
        )
    }

    from(sourceSets.main.get().output)
    from(shirudoConfigDir)
    relocate("org.objectweb.asm", "io.ohmyrasp.agent.shaded.asm")
    exclude("**/module-info.class", "META-INF/versions/**")
}

val verifyShirudoUpatchJar = tasks.register("verifyShirudoUpatchJar") {
    group = "verification"
    description = "Verifies the Java 11 shirudo upatch jar size, manifest, baked config, and bytecode."
    dependsOn(shirudoUpatchJar)

    doLast {
        val jarFile = shirudoUpatchJar.get().archiveFile.get().asFile
        require(jarFile.isFile) {
            "Missing shirudo upatch jar: ${jarFile.absolutePath}"
        }
        val maxBytes = 16L * 1024L * 1024L
        require(jarFile.length() in 1 until maxBytes) {
            "Expected shirudo upatch jar size < 16 MiB, got ${jarFile.length()} bytes"
        }
        ZipFile(jarFile).use { zip ->
            val manifestEntry = zip.getEntry("META-INF/MANIFEST.MF")
                ?: error("Missing META-INF/MANIFEST.MF in ${jarFile.name}")
            val manifestBytes = zip.getInputStream(manifestEntry).use { it.readBytes() }
            val manifestText = manifestBytes.toString(Charsets.UTF_8)
            val mainSection = manifestText.split(Regex("\\r?\\n\\r?\\n"), limit = 2).first()
            require(mainSection.lineSequence().any { it.startsWith("Premain-Class:") }) {
                "Expected Premain-Class: in main manifest section of ${jarFile.name}"
            }
            val manifest = Manifest(ByteArrayInputStream(manifestBytes))
            require(manifest.mainAttributes.getValue("Premain-Class") == "io.ohmyrasp.agent.launch.AgentLauncher") {
                "Unexpected Premain-Class in ${jarFile.name}"
            }
            require(manifest.mainAttributes.getValue("Agent-Class") == "io.ohmyrasp.agent.launch.AgentLauncher") {
                "Unexpected Agent-Class in ${jarFile.name}"
            }
            require(manifest.mainAttributes.getValue("OhMyRasp-Shirudo-Upatch") == "true") {
                "Missing OhMyRasp-Shirudo-Upatch: true in ${jarFile.name}"
            }

            val configEntry = zip.getEntry("META-INF/ohmyrasp-shirudo.properties")
                ?: error("Missing META-INF/ohmyrasp-shirudo.properties in ${jarFile.name}")
            val props = Properties()
            zip.getInputStream(configEntry).use { props.load(it) }
            require(props.getProperty("standalone") == "true") {
                "Expected standalone=true, got ${props.getProperty("standalone")}"
            }
            require(props.getProperty("lock_config") == shirudoLockConfig) {
                "Expected lock_config=$shirudoLockConfig, got ${props.getProperty("lock_config")}"
            }
            require(props.getProperty("mode") == shirudoMode) {
                "Expected mode=$shirudoMode, got ${props.getProperty("mode")}"
            }
            require(props.getProperty("control") == "none") {
                "Expected control=none, got ${props.getProperty("control")}"
            }
            require(props.getProperty("log") == "stderr") {
                "Expected log=stderr, got ${props.getProperty("log")}"
            }
            require(props.getProperty("latency_sample") == "0") {
                "Expected latency_sample=0, got ${props.getProperty("latency_sample")}"
            }

            val classEntries = zip.entries().asSequence()
                .filter { !it.isDirectory && it.name.endsWith(".class") }
                .toList()
            require(classEntries.isNotEmpty()) {
                "No Java 11 era agent classes were packaged in ${jarFile.name}."
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
    dependsOn(agentJava11Jar, shirudoUpatchJar)
}

tasks.check {
    dependsOn(verifyJava11AgentBytecode, verifyShirudoUpatchJar)
}
