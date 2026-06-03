plugins {
    war
}

dependencies {
    providedCompile("jakarta.servlet:jakarta.servlet-api:latest.release")
    implementation("commons-jxpath:commons-jxpath:latest.release")
    implementation("com.h2database:h2:latest.release")
    implementation("org.apache.velocity:velocity-engine-core:latest.release")
    implementation("org.springframework:spring-context:latest.release")
    implementation("org.springframework:spring-expression:latest.release")
}

tasks.war {
    archiveFileName.set("playground.war")
}
