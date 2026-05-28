plugins {
    kotlin("jvm")
    id("maven-publish")
}

group = "com.github.autodiag2"
version = property("VERSION_NAME") as String

dependencies {
    testImplementation(kotlin("test"))
}

kotlin {
    jvmToolchain(21)
}

publishing {
    publications { 
        create<MavenPublication>("maven") { 
            from(components["java"]) 
            groupId = project.group.toString() 
            artifactId = "kotlin-pcap" 
            version = project.version.toString() 
        } 
    } 
}
