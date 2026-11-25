// Applied by the root build to agent-java8, agent-java11 and agent-java17.
//
// The three backport lines share one behaviour contract: the tests under backport-tests/ are written
// against the java8 line (package io.ohmyrasp.agent.java8, classes named Java8*). agent-java8 compiles
// that tree as it is.
val canonicalTests = rootProject.file("backport-tests/src/test/java")

extensions.getByType<SourceSetContainer>().named("test") {
    java.srcDir(canonicalTests)
}
