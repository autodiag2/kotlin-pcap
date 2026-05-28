plugins {
    kotlin("multiplatform")
    id("maven-publish")
    id("com.android.library")
}

group = "io.github.autodiag2"
version = "1.0.0"

kotlin {
    jvm()

    androidTarget()

    iosArm64()
    iosSimulatorArm64()

    linuxX64()
    macosArm64()
    mingwX64()

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