plugins {
    war
}

dependencies {
    providedCompile("jakarta.servlet:jakarta.servlet-api:5.0.0")
}

val generatedJava8JakartaSources = layout.buildDirectory.dir("generated/sources/java8Jakarta/java")

val generateJava8JakartaServlet by tasks.registering(Copy::class) {
    from(project(":playground-java8").layout.projectDirectory.dir("src/main/java"))
    into(generatedJava8JakartaSources)
    include("**/*.java")
    filter { line: String -> line.replace("javax.servlet", "jakarta.servlet") }
}

sourceSets {
    named("main") {
        java.srcDir(generatedJava8JakartaSources)
    }
}

tasks.withType<JavaCompile>().configureEach {
    dependsOn(generateJava8JakartaServlet)
    options.encoding = "UTF-8"
    options.release.set(8)
}

tasks.war {
    archiveFileName.set("playground-java8-jakarta.war")
}
