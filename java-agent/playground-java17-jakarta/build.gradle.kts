plugins {
    war
}

dependencies {
    providedCompile("jakarta.servlet:jakarta.servlet-api:6.0.0")
}

// The servlet is written once, in playground-java17 against javax.servlet. This module compiles a copy
// with the package replaced, as playground-java8-jakarta does. Edit the file in playground-java17.
val generatedJava17JakartaSources = layout.buildDirectory.dir("generated/sources/java17Jakarta/java")

val generateJava17JakartaServlet = tasks.register<Sync>("generateJava17JakartaServlet") {
    from(project(":playground-java17").layout.projectDirectory.dir("src/main/java"))
    into(generatedJava17JakartaSources)
    include("**/*.java")
    filter { line: String -> line.replace("javax.servlet", "jakarta.servlet") }
}

sourceSets {
    named("main") {
        java.srcDir(generatedJava17JakartaSources)
    }
}

tasks.withType<JavaCompile>().configureEach {
    dependsOn(generateJava17JakartaServlet)
    options.encoding = "UTF-8"
    options.release.set(17)
}

tasks.war {
    archiveFileName.set("playground-java17-jakarta.war")
}
