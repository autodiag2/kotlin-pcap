pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

rootProject.name = "kotlin-pcap"

include(
    ":pcap-core",
    ":pcapng",
    ":pcap-cli"
)