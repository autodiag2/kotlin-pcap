package io.github.autodiag2.kotlin.pcap

import java.io.Closeable
import java.io.EOFException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.nio.file.Path
import java.nio.file.StandardOpenOption

class PcapMemoryMappedReader private constructor(
    private val channel: FileChannel,
    private val buffer: ByteBuffer,
    val globalHeader: PcapGlobalHeader
) : Closeable {

    companion object {

        fun open(path: Path): PcapMemoryMappedReader {
            val channel = FileChannel.open(
                path,
                StandardOpenOption.READ
            )

            val buffer = channel.map(
                FileChannel.MapMode.READ_ONLY,
                0,
                channel.size()
            )

            val magic = buffer.int

            val order = when (magic) {
                PcapMagic.MICRO_BIG,
                PcapMagic.NANO_BIG -> ByteOrder.BIG_ENDIAN

                PcapMagic.MICRO_LITTLE,
                PcapMagic.NANO_LITTLE -> ByteOrder.LITTLE_ENDIAN

                else -> throw IllegalArgumentException("Invalid PCAP")
            }

            buffer.order(order)
            buffer.position(0)

            val header = PcapGlobalHeader(
                magic = buffer.int,
                versionMajor = buffer.short.toInt() and 0xFFFF,
                versionMinor = buffer.short.toInt() and 0xFFFF,
                thisZone = buffer.int,
                sigFigs = buffer.int,
                snapLen = buffer.int,
                network = buffer.int
            )

            return PcapMemoryMappedReader(
                channel,
                buffer,
                header
            )
        }
    }

    fun hasRemainingPacket(): Boolean {
        return buffer.remaining() >= 16
    }

    fun readPacket(): PcapPacket? {
        if (!hasRemainingPacket()) {
            return null
        }

        val tsSec = buffer.int.toLong() and 0xFFFFFFFFL
        val tsSub = buffer.int.toLong() and 0xFFFFFFFFL
        val inclLen = buffer.int
        val origLen = buffer.int

        if (buffer.remaining() < inclLen) {
            throw EOFException()
        }

        val payload = ByteArray(inclLen)
        buffer.get(payload)

        return PcapPacket(
            header = PcapPacketHeader(
                timestampSeconds = tsSec,
                timestampSubseconds = tsSub,
                capturedLength = inclLen,
                originalLength = origLen
            ),
            payload = payload
        )
    }

    override fun close() {
        channel.close()
    }
}
