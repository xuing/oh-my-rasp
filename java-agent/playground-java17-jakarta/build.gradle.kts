plugins {
    war
}

dependencies {
    providedCompile("jakarta.servlet:jakarta.servlet-api:6.0.0")
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release.set(17)
}

tasks.war {
    archiveFileName.set("playground-java17-jakarta.war")
}
