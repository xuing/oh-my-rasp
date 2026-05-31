plugins {
    war
}

dependencies {
    providedCompile("jakarta.servlet:jakarta.servlet-api:latest.release")
    implementation("com.h2database:h2:latest.release")
}

tasks.war {
    archiveFileName.set("playground.war")
}
