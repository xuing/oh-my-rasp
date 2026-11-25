plugins {
    java
    id("com.gradleup.shadow") version "9.6.1" apply false
}

allprojects {
    group = "io.ohmyrasp"
}

subprojects {
    apply(plugin = "java")

    java {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(25))
        }
    }

    if (name.startsWith("agent-")) {
        sourceSets.main { java.srcDir(rootProject.file("shared/src/main/java")) }
    }

    if (name.startsWith("playground")) {
        tasks.withType<War>().configureEach {
            webXml = rootProject.file("playground/archive-upload-web.xml")
        }
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
        options.release.set(25)
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
        // Event reporting is asynchronous in production; tests assert on the spool
        // immediately after invoking a hook, so write inline during tests.
        systemProperty("ohmyrasp.log.sync", "true")
    }
}

// Kept separate from agent packaging: these libraries run the upstream REST admission fixture.
val yarnProbeRuntime by configurations.creating {
    isCanBeConsumed = false
}
dependencies {
    val hadoop = "2.8.1"
    yarnProbeRuntime("org.apache.hadoop:hadoop-yarn-server-resourcemanager:$hadoop")
    yarnProbeRuntime("org.apache.hadoop:hadoop-yarn-common:$hadoop")
    yarnProbeRuntime("org.apache.hadoop:hadoop-common:$hadoop")
    yarnProbeRuntime("javax.servlet:javax.servlet-api:3.1.0")
}
tasks.register<Sync>("stageYarnProbe") {
    from(yarnProbeRuntime)
    into(layout.buildDirectory.dir("yarn-probe"))
}

// Reuse the servlet APIs already resolved to compile the compatibility playgrounds.
tasks.register<Sync>("stageServletProbe") {
    from(rootProject.project(":playground-java8").configurations.named("compileClasspath")) { include("javax.servlet-api-*.jar") }
    from(rootProject.project(":playground-java8-jakarta").configurations.named("compileClasspath")) { include("jakarta.servlet-api-*.jar") }
    into(layout.buildDirectory.dir("servlet-probe"))
}
