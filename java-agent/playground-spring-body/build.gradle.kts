// A Spring Boot application with a @RequestBody JSON endpoint, for java-agent/acceptance/runtime/request-body.sh.
// No Spring Boot plugin: installDist lays out the starter's runtime classpath, and the script runs the main class.
plugins {
    application
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web:3.5.16")
}

application {
    mainClass.set("io.ohmyrasp.playground.springbody.SpringBodyApplication")
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release.set(17)
}

// The same application on Jetty and on Undertow, for request-body.sh's checks of a block thrown from the
// application's read: Spring Boot runs the server it finds on the class path. installJetty and installUndertow
// lay out build/install-jetty/lib and build/install-undertow/lib as installDist lays out the Tomcat one.
val springBootServers = mapOf(
    "jetty" to "org.springframework.boot:spring-boot-starter-jetty:3.5.16",
    "undertow" to "org.springframework.boot:spring-boot-starter-undertow:3.5.16",
)
springBootServers.forEach { (server, starter) ->
    val runtime = configurations.create("${server}Runtime") {
        isCanBeConsumed = false
        extendsFrom(configurations.implementation.get())
        exclude(group = "org.springframework.boot", module = "spring-boot-starter-tomcat")
        attributes {
            attribute(Usage.USAGE_ATTRIBUTE, objects.named(Usage.JAVA_RUNTIME))
            attribute(Category.CATEGORY_ATTRIBUTE, objects.named(Category.LIBRARY))
            attribute(LibraryElements.LIBRARY_ELEMENTS_ATTRIBUTE, objects.named(LibraryElements.JAR))
            attribute(Bundling.BUNDLING_ATTRIBUTE, objects.named(Bundling.EXTERNAL))
            attribute(TargetJvmVersion.TARGET_JVM_VERSION_ATTRIBUTE, 17)
        }
    }
    dependencies.add(runtime.name, starter)
    tasks.register<Sync>("install" + server.replaceFirstChar { it.uppercase() }) {
        group = "distribution"
        description = "Lays out the application with Spring Boot's $server starter in place of Tomcat's."
        from(tasks.jar)
        from(runtime)
        into(layout.buildDirectory.dir("install-$server/lib"))
    }
}
