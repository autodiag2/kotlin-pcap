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
}