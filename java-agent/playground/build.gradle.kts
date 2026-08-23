plugins {
    war
}

dependencies {
    // Shared by Tomcat 10.1 and 11; 6.0 is the newest common Servlet API.
    providedCompile("jakarta.servlet:jakarta.servlet-api:6.0.0")
    implementation("commons-jxpath:commons-jxpath:1.4.0")
    implementation("com.h2database:h2:2.4.240")
    implementation("org.apache.velocity:velocity-engine-core:2.4.1")
    implementation("org.springframework:spring-context:7.0.9")
    implementation("org.springframework:spring-expression:7.0.9")
}

tasks.war {
    archiveFileName.set("playground.war")
}
