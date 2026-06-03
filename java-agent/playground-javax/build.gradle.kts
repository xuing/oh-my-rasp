plugins {
    war
}

val generatedJava = layout.buildDirectory.dir("generated/sources/javax/main/java")

val generateJavaxSources by tasks.registering(Sync::class) {
    from(project(":playground").projectDir.resolve("src/main/java")) {
        include("**/*.java")
        filter { line: String ->
            line.replace("jakarta.servlet", "javax.servlet")
        }
    }
    into(generatedJava)
}

sourceSets {
    main {
        java.srcDir(generatedJava)
        resources.srcDir(project(":playground").projectDir.resolve("src/main/resources"))
    }
}

dependencies {
    providedCompile("javax.servlet:javax.servlet-api:4.0.1")
    implementation("commons-jxpath:commons-jxpath:latest.release")
    implementation("com.h2database:h2:latest.release")
    implementation("org.apache.velocity:velocity-engine-core:latest.release")
    implementation("org.springframework:spring-context:latest.release")
    implementation("org.springframework:spring-expression:latest.release")
}

tasks.compileJava {
    dependsOn(generateJavaxSources)
}

tasks.war {
    dependsOn(generateJavaxSources)
    archiveFileName.set("playground-javax.war")
    webAppDirectory.set(project(":playground").layout.projectDirectory.dir("src/main/webapp"))
}
