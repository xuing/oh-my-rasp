plugins {
    java
    id("com.gradleup.shadow") version "9.4.1" apply false
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
