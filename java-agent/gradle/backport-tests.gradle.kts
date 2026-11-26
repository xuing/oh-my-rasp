// Applied by the root build to agent-java8, agent-java11 and agent-java17.
//
// The three backport lines share one behaviour contract: the tests under backport-tests/ are written
// against the java8 line (package io.ohmyrasp.agent.java8, classes named Java8*). agent-java8 compiles
// that tree as it is. agent-java11 and agent-java17 compile a copy that generateBackportTests writes
// into build/generated/backport-tests, applying the replacement table below. Edit the canonical file,
// never the generated copy: every generated file starts with a comment that names its canonical file.
//
// Tests that only one line can run stay in that line's own src/test and say why in their first line.
val canonicalTests = rootProject.file("backport-tests/src/test/java")
val testSources = extensions.getByType<SourceSetContainer>().named("test")

// The resources hold no line token (META-INF/services names the line-neutral LineStartListener, which starts the
// line before any test runs), so every line reads them as they are.
testSources.configure { resources.srcDir(rootProject.file("backport-tests/src/test/resources")) }

val line = name.removePrefix("agent-java")
if (line == "8") {
    testSources.configure { java.srcDir(canonicalTests) }
} else {
    // Explicit and ordered: more specific tokens first. There is no blanket "8" to "11" replacement.
    val replacements = listOf(
        "io.ohmyrasp.agent.java8" to "io.ohmyrasp.agent.java$line",   // package and imports
        "io/ohmyrasp/agent/java8" to "io/ohmyrasp/agent/java$line",   // slash form (file path, class resource names)
        "ohmyrasp.java8" to "ohmyrasp.java$line",                     // system-property prefix
        "ohmyrasp-java8-" to "ohmyrasp-java$line-",                   // temp file name prefix
        "/tmp/java8-" to "/tmp/java$line-",                           // temp path prefix
        "OHMYRASP-JAVA8" to "OHMYRASP-JAVA$line",                     // log prefix
        "OHMYRASP_JAVA8_" to "OHMYRASP_JAVA${line}_",                 // environment-variable prefix
        "java8_" to "java${line}_",                                   // detection id prefix
        "java8SysWins" to "java${line}SysWins",                       // local variable
        "Java8" to "Java$line",                                       // class and fixture-method name prefix
        "Opcodes.V1_8" to "Opcodes.V$line",                           // ASM class file version
        "Java 8" to "Java $line",                                     // message text
    )
    // After the table has run, a remaining java8 token means the table is missing a rule. Fail the
    // build instead of letting a generated copy quietly keep java8 behaviour.
    val leftover = Regex("(?i)java[ -]?8|\\bV1_8\\b")

    fun rewrite(text: String) = replacements.fold(text) { acc, (from, to) -> acc.replace(from, to) }

    val generate = tasks.register<Sync>("generateBackportTests") {
        group = "verification"
        description = "Generates the java$line copy of the canonical backport tests."
        inputs.property("replacements", replacements.toString())
        from(canonicalTests)
        into(layout.buildDirectory.dir("generated/backport-tests/java"))
        eachFile {
            val canonicalPath = path
            var first = true
            filter { text: String ->
                val converted = rewrite(text)
                check(!leftover.containsMatchIn(converted)) {
                    "backport-tests/src/test/java/$canonicalPath still has a java8 token after the replacement " +
                        "table in gradle/backport-tests.gradle.kts: ${text.trim()}"
                }
                if (first) {
                    first = false
                    "// GENERATED from backport-tests/src/test/java/$canonicalPath. Edit that file, not this copy.\n$converted"
                } else {
                    converted
                }
            }
            path = rewrite(path)
        }
        includeEmptyDirs = false
    }

    testSources.configure {
        java.srcDir(files(layout.buildDirectory.dir("generated/backport-tests/java")).builtBy(generate))
    }
}
