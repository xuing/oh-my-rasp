import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
import java.util.Properties
import java.util.jar.Manifest
import java.util.zip.ZipFile

plugins {
    java
    id("com.gradleup.shadow")
}

dependencies {
    implementation("org.ow2.asm:asm:9.11.1")
    implementation("org.ow2.asm:asm-commons:9.11.1")

    testImplementation("com.alibaba:fastjson:1.2.83")
    testImplementation("com.github.pagehelper:pagehelper:4.2.1") { isTransitive = false }
    testImplementation("org.apache.commons:commons-jexl:2.1.1") { isTransitive = false }
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
    options.release.set(8)
}

tasks.jar {
    archiveBaseName.set("ohmyrasp-agent-java8-thin")
}

val agentJava8Jar = tasks.register<ShadowJar>("agentJava8Jar") {
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

val verifyJava8AgentBytecode = tasks.register("verifyJava8AgentBytecode") {
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

val shirudoMode = providers.gradleProperty("shirudoMode").orElse("block")
val shirudoLockConfig = providers.gradleProperty("shirudoLockConfig").orElse("true")

val generateShirudoProperties = tasks.register("generateShirudoProperties") {
    group = "build"
    description = "Generates META-INF/ohmyrasp-shirudo.properties for the shirudo upatch jar."
    val outputDir = layout.buildDirectory.dir("generated/shirudo-resources")
    inputs.property("shirudoMode", shirudoMode)
    inputs.property("shirudoLockConfig", shirudoLockConfig)
    outputs.dir(outputDir)

    doLast {
        val propsFile = outputDir.get().file("META-INF/ohmyrasp-shirudo.properties").asFile
        propsFile.parentFile.mkdirs()
        propsFile.writeText(
            """
            standalone=true
            lock_config=${shirudoLockConfig.get()}
            mode=${shirudoMode.get()}
            control=none
            log=stderr
            latency_sample=0
            """.trimIndent() + "\n",
            Charsets.UTF_8
        )
    }
}

val shirudoUpatchJar = tasks.register<ShadowJar>("shirudoUpatchJar") {
    group = "build"
    description = "Builds the standalone shirudo upatch Java 8 era agent jar."
    archiveBaseName.set("ohmyrasp-java8")
    archiveClassifier.set("")
    archiveVersion.set("")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    configurations = listOf(project.configurations.runtimeClasspath.get())

    manifest {
        attributes(
            "Premain-Class" to "io.ohmyrasp.agent.java8.OhMyRaspJava8Agent",
            "Agent-Class" to "io.ohmyrasp.agent.java8.OhMyRaspJava8Agent",
            "Can-Redefine-Classes" to "true",
            "Can-Retransform-Classes" to "true",
            "Implementation-Title" to "OhMyRasp Java 8 Era Agent (shirudo upatch)",
            "OhMyRasp-Shirudo-Upatch" to "true"
        )
    }

    from(sourceSets.main.get().output)
    from(generateShirudoProperties)
    relocate("org.objectweb.asm", "io.ohmyrasp.agent.shaded.asm")
    exclude("**/module-info.class", "META-INF/versions/**")
}

val verifyShirudoUpatchJar = tasks.register("verifyShirudoUpatchJar") {
    group = "verification"
    description = "Verifies the standalone shirudo upatch Java 8 era agent jar."
    dependsOn(shirudoUpatchJar)

    doLast {
        val jarFile = shirudoUpatchJar.get().archiveFile.get().asFile
        require(jarFile.isFile) {
            "Missing shirudo upatch jar: ${jarFile.absolutePath}"
        }
        val maxSizeBytes = 16L * 1024L * 1024L
        require(jarFile.length() > 0L && jarFile.length() < maxSizeBytes) {
            "Expected shirudo upatch jar size in (0, $maxSizeBytes), got ${jarFile.length()}"
        }

        ZipFile(jarFile).use { zip ->
            val manifestEntry = zip.getEntry("META-INF/MANIFEST.MF")
            require(manifestEntry != null) {
                "Missing META-INF/MANIFEST.MF in ${jarFile.name}"
            }
            val manifestText = zip.getInputStream(manifestEntry).bufferedReader(Charsets.UTF_8).use {
                it.readText()
            }
            val mainSection = manifestText.split(Regex("\\r?\\n\\r?\\n"), limit = 2)[0]
            require(mainSection.contains("Premain-Class:")) {
                "Expected Premain-Class: in main manifest section"
            }
            require(!mainSection.contains("Boot-Class-Path:")) {
                "Boot-Class-Path: must NOT be present in shirudo upatch manifest"
            }
            val parsedManifest = zip.getInputStream(manifestEntry).use { Manifest(it) }
            val mainAttrs = parsedManifest.mainAttributes
            require(mainAttrs.getValue("Premain-Class") == "io.ohmyrasp.agent.java8.OhMyRaspJava8Agent") {
                "Unexpected Premain-Class: ${mainAttrs.getValue("Premain-Class")}"
            }
            require(mainAttrs.getValue("Boot-Class-Path") == null) {
                "Boot-Class-Path attribute must NOT be present"
            }
            require(mainAttrs.getValue("OhMyRasp-Shirudo-Upatch") == "true") {
                "Expected OhMyRasp-Shirudo-Upatch=true in manifest"
            }

            val propsEntry = zip.getEntry("META-INF/ohmyrasp-shirudo.properties")
            require(propsEntry != null) {
                "Missing META-INF/ohmyrasp-shirudo.properties in ${jarFile.name}"
            }
            val props = Properties()
            zip.getInputStream(propsEntry).use { input ->
                props.load(input.reader(Charsets.UTF_8))
            }
            val expectedKeys = listOf("standalone", "lock_config", "mode", "control", "log", "latency_sample")
            expectedKeys.forEach { key ->
                val value = props.getProperty(key)
                require(!value.isNullOrBlank()) {
                    "Missing or blank key '$key' in META-INF/ohmyrasp-shirudo.properties"
                }
            }
            require(props.getProperty("standalone") == "true") {
                "Expected standalone=true, got ${props.getProperty("standalone")}"
            }
            require(props.getProperty("lock_config") == shirudoLockConfig.get()) {
                "Expected lock_config=${shirudoLockConfig.get()}, got ${props.getProperty("lock_config")}"
            }
            require(props.getProperty("mode") == shirudoMode.get()) {
                "Expected mode=${shirudoMode.get()}, got ${props.getProperty("mode")}"
            }

            val classEntries = zip.entries().asSequence()
                .filter { !it.isDirectory && it.name.endsWith(".class") }
                .toList()
            require(classEntries.isNotEmpty()) {
                "No classes packaged in ${jarFile.name}"
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

tasks.check {
    dependsOn(verifyJava8AgentBytecode, verifyShirudoUpatchJar)
}
