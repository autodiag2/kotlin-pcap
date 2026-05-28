package io.github.autodiag2.kotlin.pcap

import java.io.BufferedOutputStream
import java.io.Closeable
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Path

class PcapWriter(
    private val output: OutputStream,
    val globalHeader: PcapGlobalHeader
) : Closeable {

    private val order = when (globalHeader.byteOrder) {
        PcapByteOrder.BIG_ENDIAN -> ByteOrder.BIG_ENDIAN
        PcapByteOrder.LITTLE_ENDIAN -> ByteOrder.LITTLE_ENDIAN
    }

    init {
        writeGlobalHeader()
    }

    companion object {

        fun toFile(
            file: java.io.File,
            header: PcapGlobalHeader
        ): PcapWriter {
            return PcapWriter(
                BufferedOutputStream(file.outputStream()),
                header
            )
        }

        fun toPath(
            path: Path,
            header: PcapGlobalHeader
        ): PcapWriter {
            return toFile(path.toFile(), header)
        }
    }

    private fun writeGlobalHeader() {
        val bb = ByteBuffer.allocate(24)
            .order(order)

        bb.putInt(globalHeader.magic)
        bb.putShort(globalHeader.versionMajor.toShort())
        bb.putShort(globalHeader.versionMinor.toShort())
        bb.putInt(globalHeader.thisZone)
        bb.putInt(globalHeader.sigFigs)
        bb.putInt(globalHeader.snapLen)
        bb.putInt(globalHeader.network)

        output.write(bb.array())
    }

    fun writePacket(packet: PcapPacket) {
        val bb = ByteBuffer.allocate(16)
            .order(order)

        bb.putInt(packet.header.timestampSeconds.toInt())
        bb.putInt(packet.header.timestampSubseconds.toInt())
        bb.putInt(packet.header.capturedLength)
        bb.putInt(packet.header.originalLength)

        output.write(bb.array())
        output.write(packet.payload)
    }

    fun writePacket(
        timestampSeconds: Long,
        timestampSubseconds: Long,
        payload: ByteArray,
        originalLength: Int = payload.size
    ) {
        writePacket(
            PcapPacket(
                header = PcapPacketHeader(
                    timestampSeconds = timestampSeconds,
                    timestampSubseconds = timestampSubseconds,
                    capturedLength = payload.size,
                    originalLength = originalLength
                ),
                payload = payload
            )
        )
    }

    override fun close() {
        output.flush()
        output.close()
    }
}
