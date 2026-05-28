plugins {
    kotlin("multiplatform")
    id("maven-publish")
    id("com.android.library")
}

group = "com.github.autodiag2"
version = property("VERSION_NAME") as String

kotlin {
    jvm()

    androidTarget()

    js(IR) {
        browser()
        nodejs()
    }

    sourceSets {
        commonMain.dependencies {
        }

        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}

android {
    namespace = "pcap.core"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
    }
}
