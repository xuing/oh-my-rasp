plugins {
    war
}

dependencies {
    providedCompile("jakarta.servlet:jakarta.servlet-api:6.0.0")
}

// The servlet is written once, in playground-java11 against javax.servlet. This module compiles a copy
// with the package replaced, as playground-java8-jakarta does. Edit the file in playground-java11.
val generatedJava11JakartaSources = layout.buildDirectory.dir("generated/sources/java11Jakarta/java")

val generateJava11JakartaServlet = tasks.register<Sync>("generateJava11JakartaServlet") {
    from(project(":playground-java11").layout.projectDirectory.dir("src/main/java"))
    into(generatedJava11JakartaSources)
    include("**/*.java")
    filter { line: String -> line.replace("javax.servlet", "jakarta.servlet") }
}

sourceSets {
    named("main") {
        java.srcDir(generatedJava11JakartaSources)
    }
}

tasks.withType<JavaCompile>().configureEach {
    dependsOn(generateJava11JakartaServlet)
    options.encoding = "UTF-8"
    options.release.set(11)
}

tasks.war {
    archiveFileName.set("playground-java11-jakarta.war")
}
