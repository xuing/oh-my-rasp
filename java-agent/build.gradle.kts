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

    if (name in setOf("agent-java8", "agent-java11", "agent-java17")) {
        apply(from = rootProject.file("gradle/backport-tests.gradle.kts"))
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

// A real transport codec for the isolated release check; it is outside the agent classpaths.
tasks.register<Sync>("stageElasticLz4Probe") {
    val release = rootProject.dependencies.create("org.elasticsearch:elasticsearch:8.19.23")
    from(rootProject.configurations.detachedConfiguration(release))
    into(layout.buildDirectory.dir("elastic-lz4-probe"))
}

// Exercise the bean lifecycle on Java 8-compatible Spring and the actual primary playground libraries.
tasks.register<Sync>("stageSpringProcessProbe") {
    val legacy = listOf("spring-context", "spring-web").map {
        rootProject.dependencies.create("org.springframework:$it:5.3.39")
    }
    into("legacy") { from(rootProject.configurations.detachedConfiguration(*legacy.toTypedArray())) }
    into("modern") {
        from(rootProject.project(":playground").configurations.named("runtimeClasspath"))
        include("spring-*.jar", "commons-logging-*.jar", "micrometer-*.jar")
    }
    into(layout.buildDirectory.dir("spring-process-probe"))
}

// The runtime fixture only uses the vendor-fixed release. The older JARs are read as data by the layout audit.
tasks.register<Sync>("stageOpenWireProbe") {
    for ((folder, release) in mapOf("fixed" to "5.15.16", "layout" to "5.17.3")) {
        val modules = listOf("activemq-client", "activemq-openwire-legacy").map {
            rootProject.dependencies.create("org.apache.activemq:$it:$release@jar")
        }
        into(folder) {
            from(rootProject.configurations.detachedConfiguration(*modules.toTypedArray()).apply { isTransitive = false })
        }
    }
    into(layout.buildDirectory.dir("openwire-probe"))
}

// Local DTO round trips only; these codecs are not agent runtime dependencies.
tasks.register<Sync>("stageHessianProbe") {
    val dubbo = "2.7.3"
    val libraries = listOf("com.caucho:hessian:4.0.66@jar", "com.alibaba:hessian-lite:3.2.13@jar",
        "org.apache.dubbo:dubbo-common:$dubbo@jar", "org.apache.dubbo:dubbo-serialization-api:$dubbo@jar",
        "org.apache.dubbo:dubbo-serialization-hessian2:$dubbo@jar").map { rootProject.dependencies.create(it) }
    from(rootProject.configurations.detachedConfiguration(*libraries.toTypedArray()).apply { isTransitive = false })
    into(layout.buildDirectory.dir("hessian-probe"))
}

// The Apache XML-RPC parser and its codec utility are used only by the in-memory RPC fixture.
tasks.register<Sync>("stageXmlRpcProbe") {
    val parser = rootProject.dependencies.create("org.apache.xmlrpc:xmlrpc-common:3.1.3")
    from(rootProject.configurations.detachedConfiguration(parser)) {
        include("xmlrpc-common-*.jar", "ws-commons-util-*.jar")
    }
    into(layout.buildDirectory.dir("xmlrpc-probe"))
}

// Fixed library versions exercise ordinary functor values on both API lines.
tasks.register<Sync>("stageCollectionsProbe") {
    val modules = listOf("commons-collections:commons-collections:3.2.2@jar",
        "org.apache.commons:commons-collections4:4.6.0@jar").map { rootProject.dependencies.create(it) }
    from(rootProject.configurations.detachedConfiguration(*modules.toTypedArray()).apply { isTransitive = false })
    into(layout.buildDirectory.dir("collections-probe"))
}
