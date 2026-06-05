plugins {
    war
}

dependencies {
    providedCompile("javax.servlet:javax.servlet-api:3.1.0")
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release.set(8)
}

tasks.war {
    archiveFileName.set("playground-java8.war")
}
