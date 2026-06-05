plugins {
    war
}

dependencies {
    providedCompile("javax.servlet:javax.servlet-api:4.0.1")
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release.set(11)
}

tasks.war {
    archiveFileName.set("playground-java11.war")
}
