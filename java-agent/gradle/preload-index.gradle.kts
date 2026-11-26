// Applied by the root build to agent-java8, agent-java11 and agent-java17.
//
// Writes META-INF/ohmyrasp/preload/<module>.txt into the module's main output: the binary name of every class of
// this module and of :shared, one per line, and of each ASM class those use, directly or through other ASM classes,
// under the name the agent JARs relocate it to. The line's entry class loads and initialises each of them before it
// registers a transformer (io.ohmyrasp.agent.util.Preload), so no hook and no transformer loads a class of ours
// for the first time inside an instrumented JDK call, where loading a class can re-enter the hook. Left out: the
// launcher package (the launcher and the entry classes, loaded before the line starts, one of which per JAR) and
// the module's entry class (the system class loader defines it before the line appends its JAR to the bootstrap
// search). The universal JAR carries the three lists and each line reads its own, so a line never loads another
// line's classes. The rule-cases probe fails when a class of ours loads during an operation.
import java.util.zip.ZipFile

/** The classes a class file names in its constant pool, by internal name. An object, so the task action captures no script. */
object PreloadClassRefs {
    fun of(bytes: ByteArray): Set<String> {
        val input = java.io.DataInputStream(bytes.inputStream())
        input.skipBytes(8)
        val count = input.readUnsignedShort()
        val utf8 = arrayOfNulls<String>(count)
        val classIndexes = mutableListOf<Int>()
        val descriptorIndexes = mutableListOf<Int>()
        var i = 1
        while (i < count) {
            when (val tag = input.readUnsignedByte()) {
                1 -> utf8[i] = input.readUTF()
                7 -> classIndexes += input.readUnsignedShort()
                8, 16, 19, 20 -> input.skipBytes(2)
                3, 4 -> input.skipBytes(4)
                5, 6 -> { input.skipBytes(8); i++ }
                9, 10, 11, 17, 18 -> input.skipBytes(4)
                12 -> { input.skipBytes(2); descriptorIndexes += input.readUnsignedShort() }
                15 -> input.skipBytes(3)
                else -> error("constant pool tag $tag")
            }
            i++
        }
        val names = mutableSetOf<String>()
        for (index in classIndexes) utf8[index]?.let { names += it.trimStart('[').removePrefix("L").removeSuffix(";") }
        for (index in descriptorIndexes) utf8[index]?.let { d -> Regex("L([^;]+);").findAll(d).forEach { names += it.groupValues[1] } }
        return names
    }
}

val preloadModule = name
// The class the launcher starts: the system class loader defines it before the line appends its JAR to the
// bootstrap search, so loading it again there would define a second, unused copy.
val entryClass = if (name == "agent-jdk25") "io/ohmyrasp/agent/OhMyRaspAgent.class"
    else name.removePrefix("agent-").let { "io/ohmyrasp/agent/$it/OhMyRaspJava${it.removePrefix("java")}Agent.class" }
val preloadDir = layout.buildDirectory.dir("generated/preload-index")
val runtimeJars = configurations.named("runtimeClasspath").map { classpath -> classpath.filter { it.name.endsWith(".jar") } }
val ownClasses = extensions.getByType<SourceSetContainer>().named("main").map { it.java.destinationDirectory }

val generatePreloadIndex = tasks.register("generatePreloadIndex") {
    group = "build"
    description = "Lists the classes the line loads before it registers a transformer."
    val jarsOnClasspath = runtimeJars
    val own = ownClasses.flatMap { it }
    val output = preloadDir
    val module = preloadModule
    val entry = entryClass
    inputs.files(jarsOnClasspath).withPropertyName("runtimeJars")
    inputs.dir(own).withPropertyName("ownClasses")
    outputs.dir(output)
    dependsOn(tasks.named("compileJava"))
    doLast {
        val asmPrefix = "org/objectweb/asm/"
        fun ours(path: String) = path.startsWith("io/ohmyrasp/agent/") && !path.startsWith("io/ohmyrasp/agent/launch/") &&
            !path.startsWith("io/ohmyrasp/agent/shaded/") && !path.endsWith("module-info") &&
            !path.endsWith("package-info") && "$path.class" != entry
        val classes = mutableMapOf<String, ByteArray>()   // ours, by internal name
        val asm = mutableMapOf<String, ByteArray>()       // ASM, by internal name
        val jars = jarsOnClasspath.get().files
        check(jars.any { it.name == "ohmyrasp-agent-shared.jar" }) { "no :shared JAR on the runtime classpath: $jars" }
        for (jar in jars) ZipFile(jar).use { zip ->
            for (e in zip.entries()) {
                if (e.isDirectory || !e.name.endsWith(".class")) continue
                val name = e.name.removeSuffix(".class")
                val target = when {
                    jar.name == "ohmyrasp-agent-shared.jar" && ours(name) -> classes
                    name.startsWith(asmPrefix) -> asm
                    else -> null
                } ?: continue
                target[name] = zip.getInputStream(e).use { it.readBytes() }
            }
        }
        val root = own.get().asFile
        check(root.resolve(entry).isFile) { "the entry class $entry is not in $root" }
        root.walkTopDown().filter { it.isFile && it.name.endsWith(".class") }.forEach {
            val name = it.relativeTo(root).invariantSeparatorsPath.removeSuffix(".class")
            if (ours(name)) classes[name] = it.readBytes()
        }
        // The ASM classes ours use, and what those use in turn.
        val asmUsed = sortedSetOf<String>()
        val pending = ArrayDeque(classes.values.flatMap { PreloadClassRefs.of(it) }.filter { it.startsWith(asmPrefix) })
        while (pending.isNotEmpty()) {
            val next = pending.removeFirst()
            val bytes = asm[next] ?: continue
            if (asmUsed.add(next)) pending += PreloadClassRefs.of(bytes).filter { it.startsWith(asmPrefix) && it !in asmUsed }
        }
        val names = sortedSetOf<String>()
        classes.keys.forEach { names += it.replace('/', '.') }
        asmUsed.forEach { names += "io.ohmyrasp.agent.shaded.asm." + it.removePrefix(asmPrefix).replace('/', '.') }
        val file = output.get().file("META-INF/ohmyrasp/preload/$module.txt").asFile
        file.parentFile.mkdirs()
        file.writeText(names.joinToString("") { it + "\n" })
    }
}

extensions.getByType<SourceSetContainer>().named("main") {
    output.dir(mapOf("builtBy" to generatePreloadIndex), preloadDir)
}
