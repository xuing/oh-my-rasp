plugins {
    war
}

val generatedJava = layout.buildDirectory.dir("generated/sources/javax/main/java")

val generateJavaxSources = tasks.register<Sync>("generateJavaxSources") {
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
    implementation("commons-jxpath:commons-jxpath:1.4.0")
    implementation("com.h2database:h2:2.4.240")
    implementation("org.apache.velocity:velocity-engine-core:2.4.1")
    implementation("org.springframework:spring-context:7.0.8")
    implementation("org.springframework:spring-expression:7.0.8")
}

tasks.compileJava {
    dependsOn(generateJavaxSources)
}

tasks.war {
    dependsOn(generateJavaxSources)
    archiveFileName.set("playground-javax.war")
    webAppDirectory.set(project(":playground").layout.projectDirectory.dir("src/main/webapp"))
}
