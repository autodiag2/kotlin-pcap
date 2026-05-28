The missing pure kotlin parser and serializer library  
Want pcap fmt without relying on jni ?  
use kotlin-pcap  
# kotlin-pcap Installation

## Gradle dependency (recommended)

### settings.gradle.kts

```kotlin
dependencyResolutionManagement {
    repositories {
        mavenCentral()

        maven {
            url = uri("https://jitpack.io")
        }
    }
}
```

### build.gradle.kts

```kotlin
dependencies {
    implementation(
        "com.github.autodiag2.kotlin-pcap:pcap-core:1.0.0"
    )
}
```

## Using latest development version

```kotlin
dependencies {
    implementation(
        "com.github.autodiag2.kotlin-pcap:pcap-core:master-SNAPSHOT"
    )
}
```

## From sources

### Add git submodule

```bash
git submodule add \
https://github.com/autodiag2/kotlin-pcap.git
```

### Project layout

```text
your-project/
├── build.gradle.kts
├── settings.gradle.kts
├── kotlin-pcap/
└── app/
```

### settings.gradle.kts

```kotlin
include(":kotlin-pcap:pcap-core")
```

### build.gradle.kts

```kotlin
dependencies {
    implementation(project(":kotlin-pcap:pcap-core"))
}
```

## Build from sources

```bash
git clone \
https://github.com/autodiag2/kotlin-pcap.git

cd kotlin-pcap

./gradlew build
```

## Run tests

```bash
./gradlew test
```

## JVM example

```kotlin
import com.github.autodiag2.kotlin.pcap.PcapByteOrder
import com.github.autodiag2.kotlin.pcap.PcapLinkType
import com.github.autodiag2.kotlin.pcap.PcapUtil
import com.github.autodiag2.kotlin.pcap.PcapWriter

fun main() {

    val header = PcapUtil.createMicroHeader(
        byteOrder = PcapByteOrder.LITTLE_ENDIAN,
        network = PcapLinkType.ETHERNET
    )

    PcapWriter.toFile(
        java.io.File("capture.pcap"),
        header
    ).use { writer ->

        writer.writePacket(
            timestampSeconds = 1,
            timestampSubseconds = 0,
            payload = byteArrayOf(
                0x01,
                0x02,
                0x03
            )
        )
    }
}
```

## Packet serialization example

```kotlin
import com.github.autodiag2.kotlin.pcap.packet.Ethernet
import com.github.autodiag2.kotlin.pcap.packet.IPv4
import com.github.autodiag2.kotlin.pcap.packet.TCP

val tcp = TCP(
    sourcePort = 5555,
    destinationPort = 80,
    payload = "hello".encodeToByteArray()
)

val ipv4 = IPv4(
    sourceIp = byteArrayOf(
        192.toByte(),
        168.toByte(),
        1,
        10
    ),
    destinationIp = byteArrayOf(
        1,
        1,
        1,
        1
    ),
    protocol = 6,
    payload = tcp
)

val ethernet = Ethernet(
    destinationMac = byteArrayOf(
        1,
        2,
        3,
        4,
        5,
        6
    ),
    sourceMac = byteArrayOf(
        6,
        5,
        4,
        3,
        2,
        1
    ),
    etherType = 0x0800,
    payload = ipv4
)

val raw = ethernet.serialize()
```
