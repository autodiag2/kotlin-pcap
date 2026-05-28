plugins {
    kotlin("android")
    id("com.android.library")
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

android {
    namespace = "pcap.core"

    compileSdk = 36

    defaultConfig {
        minSdk = 24
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

afterEvaluate { 
    publishing { 
        publications { 
            create<MavenPublication>("release") { 
                from(components["release"])
                groupId = "com.github.autodiag2" 
                artifactId = "kotlin-pcap"
                version = project.version.toString() 
             } 
         } 
     } 
}
