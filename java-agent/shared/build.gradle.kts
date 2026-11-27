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

// The agent JARs' entry classes (io.ohmyrasp.agent.launch.*Entry) are class-file version 49, so a Java 6
// or 7 JVM can load them and report that no line fits instead of aborting. javac cannot emit version 49,
// so EntryGenerator writes them with ASM and the directory it writes joins this module's main output:
// the JAR, the test classpath and every agent JAR get them as if compiled here.
val entryGenerator: SourceSet by sourceSets.creating
dependencies {
    "entryGeneratorImplementation"("org.ow2.asm:asm:9.11.1")
}
val launcherEntriesDir = layout.buildDirectory.dir("generated/launcher-entries")
val generateLauncherEntries = tasks.register<JavaExec>("generateLauncherEntries") {
    group = "build"
    description = "Writes the version 49 launcher entry classes."
    classpath = entryGenerator.runtimeClasspath
    mainClass.set("io.ohmyrasp.agent.launch.EntryGenerator")
    val output = launcherEntriesDir
    outputs.dir(output)
    argumentProviders.add(CommandLineArgumentProvider { listOf(output.get().asFile.absolutePath) })
    doFirst { output.get().asFile.deleteRecursively() }
}
sourceSets.main {
    output.dir(mapOf("builtBy" to generateLauncherEntries), launcherEntriesDir)
}

// Tomcat's own request-body classes, one Tomcat line each (the versions probes/hook-targets/libraries.toml records
// for tomcat-embed-core): RequestBodyVisitorTest rewrites the real CoyoteInputStream and reads through Tomcat's
// own InputBuffer, whose read(ByteBuffer) contract the recorder must follow.
val tomcatBodyLines = mapOf("9" to "9.0.124", "10" to "10.1.62", "11" to "11.0.29")
val tomcatBodyClasspaths = tomcatBodyLines.map { (line, version) ->
    val configuration = configurations.create("tomcatBody$line") { isTransitive = false }
    dependencies.add(configuration.name, "org.apache.tomcat.embed:tomcat-embed-core:$version")
    line to configuration.incoming.files
}
tasks.test {
    tomcatBodyClasspaths.forEach { (_, files) -> inputs.files(files) }
    val paths = tomcatBodyClasspaths
    jvmArgumentProviders.add(CommandLineArgumentProvider {
        paths.map { (line, files) -> "-Dohmyrasp.test.tomcat$line=${files.asPath}" }
    })
}
