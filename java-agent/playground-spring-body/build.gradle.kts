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
