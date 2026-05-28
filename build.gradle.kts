plugins {
    kotlin("multiplatform") version "2.2.0" apply false
    id("com.android.library") version "8.10.0" apply false
    id("maven-publish")
}
subprojects { 
    apply(plugin = "maven-publish")
    group = rootProject.group
    version = rootProject.version 
}
