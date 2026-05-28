package io.github.autodiag2.kotlin.pcap

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import io.github.autodiag2.kotlin.pcap.packet.Ethernet
import io.github.autodiag2.kotlin.pcap.packet.IPv4
import io.github.autodiag2.kotlin.pcap.packet.Packet
import io.github.autodiag2.kotlin.pcap.packet.TCP
import io.github.autodiag2.kotlin.pcap.packet.UDP

class PcapTest {

    @Test
    fun testWriteAndReadSinglePacketLittleEndian() {
        val output = ByteArrayOutputStream()

        val header = PcapUtil.createMicroHeader(
            byteOrder = PcapByteOrder.LITTLE_ENDIAN,
            network = PcapLinkType.ETHERNET
        )

        val payload = byteArrayOf(
            0x01,
            0x02,
            0x03,
            0x04
        )

        PcapWriter(output, header).use { writer ->
            writer.writePacket(
                timestampSeconds = 100,
                timestampSubseconds = 200,
                payload = payload
            )
        }

        val bytes = output.toByteArray()

        val reader = PcapReader.fromInputStream(
            ByteArrayInputStream(bytes)
        )

        assertEquals(
            PcapByteOrder.LITTLE_ENDIAN,
            reader.globalHeader.byteOrder
        )

        assertEquals(
            PcapTimestampPrecision.MICRO,
            reader.globalHeader.precision
        )

        val packet = reader.readPacket()

        assertNotNull(packet)

        assertEquals(100, packet.header.timestampSeconds)
        assertEquals(200, packet.header.timestampSubseconds)
        assertEquals(payload.size, packet.header.capturedLength)
        assertEquals(payload.size, packet.header.originalLength)

        assertContentEquals(payload, packet.payload)

        assertNull(reader.readPacket())
    }

    @Test
    fun testWriteAndReadSinglePacketBigEndian() {
        val output = ByteArrayOutputStream()

        val header = PcapUtil.createMicroHeader(
            byteOrder = PcapByteOrder.BIG_ENDIAN,
            network = PcapLinkType.RAW
        )

        val payload = byteArrayOf(
            0x55,
            0x66,
            0x77
        )

        PcapWriter(output, header).use { writer ->
            writer.writePacket(
                timestampSeconds = 9999,
                timestampSubseconds = 8888,
                payload = payload
            )
        }

        val reader = PcapReader.fromInputStream(
            ByteArrayInputStream(output.toByteArray())
        )

        val packet = reader.readPacket()

        assertNotNull(packet)

        assertEquals(9999, packet.header.timestampSeconds)
        assertEquals(8888, packet.header.timestampSubseconds)

        assertContentEquals(payload, packet.payload)
    }

    @Test
    fun testMultiplePackets() {
        val output = ByteArrayOutputStream()

        val header = PcapUtil.createMicroHeader()

        PcapWriter(output, header).use { writer ->
            for (i in 0 until 10) {
                writer.writePacket(
                    timestampSeconds = i.toLong(),
                    timestampSubseconds = (i * 10).toLong(),
                    payload = byteArrayOf(
                        i.toByte(),
                        (i + 1).toByte()
                    )
                )
            }
        }

        val packets = PcapReader
            .fromInputStream(ByteArrayInputStream(output.toByteArray()))
            .readAll()

        assertEquals(10, packets.size)

        for (i in 0 until 10) {
            val packet = packets[i]

            assertEquals(i.toLong(), packet.header.timestampSeconds)
            assertEquals((i * 10).toLong(), packet.header.timestampSubseconds)

            assertContentEquals(
                byteArrayOf(
                    i.toByte(),
                    (i + 1).toByte()
                ),
                packet.payload
            )
        }
    }

    @Test
    fun testNanoPrecisionHeader() {
        val header = PcapUtil.createNanoHeader(
            byteOrder = PcapByteOrder.LITTLE_ENDIAN
        )

        assertEquals(
            PcapTimestampPrecision.NANO,
            header.precision
        )
    }

    @Test
    fun testHexConversion() {
        val data = byteArrayOf(
            0x00,
            0x11,
            0x22,
            0x7F,
            0x55.toByte(),
            0xFF.toByte()
        )

        val hex = PcapUtil.hex(data)

        assertEquals("0011227F55FF", hex)

        val parsed = PcapUtil.parseHex(hex)

        assertContentEquals(data, parsed)
    }

    @Test
    fun testPayloadTruncation() {
        val payload = ByteArray(100)

        val truncated = PcapUtil.truncatePayload(
            payload,
            16
        )

        assertEquals(16, truncated.size)
    }

    @Test
    fun testIterator() {
        val output = ByteArrayOutputStream()

        PcapWriter(
            output,
            PcapUtil.createMicroHeader()
        ).use { writer ->
            writer.writePacket(
                timestampSeconds = 1,
                timestampSubseconds = 2,
                payload = byteArrayOf(0x10)
            )

            writer.writePacket(
                timestampSeconds = 3,
                timestampSubseconds = 4,
                payload = byteArrayOf(0x20)
            )
        }

        val reader = PcapReader.fromInputStream(
            ByteArrayInputStream(output.toByteArray())
        )

        val packets = ArrayList<PcapPacket>()

        for (packet in reader) {
            packets += packet
        }

        assertEquals(2, packets.size)

        assertEquals(
            1,
            packets[0].header.timestampSeconds
        )

        assertEquals(
            3,
            packets[1].header.timestampSeconds
        )
    }

    @Test
    fun testInvalidMagic() {
        val bytes = byteArrayOf(
            0x00,
            0x00,
            0x00,
            0x00
        )

        assertFailsWith<IllegalArgumentException> {
            PcapReader.fromInputStream(
                ByteArrayInputStream(bytes)
            )
        }
    }

    @Test
    fun testEmptyPayloadPacket() {
        val output = ByteArrayOutputStream()

        PcapWriter(
            output,
            PcapUtil.createMicroHeader()
        ).use { writer ->
            writer.writePacket(
                timestampSeconds = 1,
                timestampSubseconds = 2,
                payload = ByteArray(0)
            )
        }

        val reader = PcapReader.fromInputStream(
            ByteArrayInputStream(output.toByteArray())
        )

        val packet = reader.readPacket()

        assertNotNull(packet)

        assertEquals(0, packet.payload.size)
    }

    @Test
    fun testLargePayload() {
        val payload = ByteArray(1024 * 1024) {
            (it and 0xFF).toByte()
        }

        val output = ByteArrayOutputStream()

        PcapWriter(
            output,
            PcapUtil.createMicroHeader()
        ).use { writer ->
            writer.writePacket(
                timestampSeconds = 1,
                timestampSubseconds = 1,
                payload = payload
            )
        }

        val reader = PcapReader.fromInputStream(
            ByteArrayInputStream(output.toByteArray())
        )

        val packet = reader.readPacket()

        assertNotNull(packet)

        assertEquals(payload.size, packet.payload.size)

        assertTrue(
            payload.contentEquals(packet.payload)
        )
    }

    @Test
    fun testReadAllEmpty() {
        val output = ByteArrayOutputStream()

        PcapWriter(
            output,
            PcapUtil.createMicroHeader()
        ).use {
        }

        val packets = PcapReader
            .fromInputStream(ByteArrayInputStream(output.toByteArray()))
            .readAll()

        assertTrue(packets.isEmpty())
    }

    @Test
    fun testSerializeUDP() {

        val udp = UDP(
            sourcePort = 1234,
            destinationPort = 5678,
            payloadData = byteArrayOf(
                0x01,
                0x02,
                0x03
            )
        )

        val bytes = udp.serialize()

        assertEquals(
            11,
            bytes.size
        )

        assertEquals(
            0x04,
            bytes[0].toInt() and 0xFF
        )

        assertEquals(
            0xD2,
            bytes[1].toInt() and 0xFF
        )

        assertEquals(
            0x16,
            bytes[2].toInt() and 0xFF
        )

        assertEquals(
            0x2E,
            bytes[3].toInt() and 0xFF
        )
    }

    @Test
    fun testSerializeTCP() {

        val tcp = TCP(
            sourcePort = 1000,
            destinationPort = 80,
            sequenceNumber = 1,
            acknowledgmentNumber = 2,
            payloadData = "hello".encodeToByteArray()
        )

        val bytes = tcp.serialize()

        assertEquals(
            25,
            bytes.size
        )

        assertEquals(
            0x03,
            bytes[0].toInt() and 0xFF
        )

        assertEquals(
            0xE8,
            bytes[1].toInt() and 0xFF
        )

        assertEquals(
            0x00,
            bytes[2].toInt() and 0xFF
        )

        assertEquals(
            0x50,
            bytes[3].toInt() and 0xFF
        )
    }

    @Test
    fun testSerializeIPv4() {

        val udp = UDP(
            sourcePort = 1111,
            destinationPort = 2222,
            payloadData = byteArrayOf(
                0x55,
                0x66
            )
        )

        val ipv4 = IPv4(
            sourceIp = byteArrayOf(
                192.toByte(),
                168.toByte(),
                1,
                10
            ),
            destinationIp = byteArrayOf(
                8,
                8,
                8,
                8
            ),
            protocol = 17,
            payload = udp
        )

        val bytes = ipv4.serialize()

        assertEquals(
            30,
            bytes.size
        )

        assertEquals(
            0x45,
            bytes[0].toInt() and 0xFF
        )

        assertEquals(
            17,
            bytes[9].toInt() and 0xFF
        )

        assertEquals(
            192,
            bytes[12].toInt() and 0xFF
        )

        assertEquals(
            8,
            bytes[16].toInt() and 0xFF
        )
    }

    @Test
    fun testSerializeEthernet() {

        val ethernet = Ethernet(
            destinationMac = byteArrayOf(
                0xFF.toByte(),
                0xFF.toByte(),
                0xFF.toByte(),
                0xFF.toByte(),
                0xFF.toByte(),
                0xFF.toByte()
            ),
            sourceMac = byteArrayOf(
                0x00,
                0x11,
                0x22,
                0x33,
                0x44,
                0x55
            ),
            etherType = 0x0800,
            payload = IPv4(
                sourceIp = byteArrayOf(
                    1,
                    1,
                    1,
                    1
                ),
                destinationIp = byteArrayOf(
                    8,
                    8,
                    8,
                    8
                ),
                protocol = 17,
                payload = UDP(
                    sourcePort = 1,
                    destinationPort = 2,
                    payloadData = byteArrayOf(
                        0x10,
                        0x20
                    )
                )
            )
        )

        val bytes = ethernet.serialize()

        assertTrue(
            bytes.size > 14
        )

        assertEquals(
            0x08,
            bytes[12].toInt() and 0xFF
        )

        assertEquals(
            0x00,
            bytes[13].toInt() and 0xFF
        )
    }

    @Test
    fun testPcapPacketFromPacket() {

        val udp = UDP(
            sourcePort = 100,
            destinationPort = 200,
            payloadData = byteArrayOf(
                0x01,
                0x02
            )
        )

        val pcapPacket = PcapPacket.fromPacket(
            header = PcapPacketHeader(
                timestampSeconds = 1,
                timestampSubseconds = 2,
                capturedLength = udp.serialize().size,
                originalLength = udp.serialize().size
            ),
            packet = udp
        )

        assertEquals(
            udp.serialize().size,
            pcapPacket.payload.size
        )

        assertContentEquals(
            udp.serialize(),
            pcapPacket.payload
        )
    }

    @Test
    fun testNestedPacketSerialization() {

        val tcp = TCP(
            sourcePort = 5555,
            destinationPort = 80,
            payloadData = "GET".encodeToByteArray()
        )

        val ipv4 = IPv4(
            sourceIp = byteArrayOf(
                10,
                0,
                0,
                1
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

        val bytes = ethernet.serialize()

        assertTrue(
            bytes.isNotEmpty()
        )

        assertTrue(
            bytes.size > 40
        )
    }
}