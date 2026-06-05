pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
    }
}

rootProject.name = "ohmyrasp"

include("agent")
include("agent-java8")
include("agent-java11")
include("agent-java17")
include("playground")
include("playground-java8")
include("playground-java8-jakarta")
include("playground-java11")
include("playground-java11-jakarta")
include("playground-java17")
include("playground-java17-jakarta")
include("playground-javax")
