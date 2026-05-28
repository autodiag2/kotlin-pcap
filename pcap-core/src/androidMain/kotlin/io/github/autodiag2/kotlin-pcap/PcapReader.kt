package io.github.autodiag2.kotlin.pcap

import java.io.BufferedInputStream
import java.io.Closeable
import java.io.EOFException
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

class PcapReader private constructor(
    private val input: InputStream,
    val globalHeader: PcapGlobalHeader
) : Closeable, Iterable<PcapPacket> {

    private val endian = globalHeader.byteOrder

    companion object {

        fun fromFile(file: java.io.File): PcapReader {
            return fromInputStream(file.inputStream())
        }

        fun fromPath(path: java.nio.file.Path): PcapReader {
            return fromInputStream(path.toFile().inputStream())
        }

        fun fromInputStream(input: InputStream): PcapReader {
            val buffered = BufferedInputStream(input)
            val rawMagic = ByteArray(4)

            readFully(buffered, rawMagic)

            val magic = ByteBuffer.wrap(rawMagic)
                .order(ByteOrder.BIG_ENDIAN)
                .int

            val order = when (magic) {
                PcapMagic.MICRO_BIG,
                PcapMagic.NANO_BIG -> ByteOrder.BIG_ENDIAN

                PcapMagic.MICRO_LITTLE,
                PcapMagic.NANO_LITTLE -> ByteOrder.LITTLE_ENDIAN

                else -> throw IllegalArgumentException("Invalid PCAP magic")
            }

            val rest = ByteArray(20)
            readFully(buffered, rest)

            val bb = ByteBuffer.allocate(24)
            bb.order(order)
            bb.putInt(magic)
            bb.put(rest)
            bb.flip()

            val header = PcapGlobalHeader(
                magic = bb.int,
                versionMajor = bb.short.toInt() and 0xFFFF,
                versionMinor = bb.short.toInt() and 0xFFFF,
                thisZone = bb.int,
                sigFigs = bb.int,
                snapLen = bb.int,
                network = bb.int
            )

            return PcapReader(buffered, header)
        }

        private fun readFully(input: InputStream, data: ByteArray) {
            var offset = 0
            while (offset < data.size) {
                val read = input.read(data, offset, data.size - offset)
                if (read < 0) {
                    throw EOFException()
                }
                offset += read
            }
        }
    }

    fun readPacket(): PcapPacket? {
        val headerBytes = ByteArray(16)

        val first = input.read()
        if (first < 0) {
            return null
        }

        headerBytes[0] = first.toByte()
        readRemaining(input, headerBytes, 1)

        val bb = ByteBuffer.wrap(headerBytes)
            .order(
                when (endian) {
                    PcapByteOrder.BIG_ENDIAN -> ByteOrder.BIG_ENDIAN
                    PcapByteOrder.LITTLE_ENDIAN -> ByteOrder.LITTLE_ENDIAN
                }
            )

        val tsSec = bb.int.toLong() and 0xFFFFFFFFL
        val tsSub = bb.int.toLong() and 0xFFFFFFFFL
        val inclLen = bb.int
        val origLen = bb.int

        require(inclLen >= 0) {
            "Negative incl_len"
        }

        require(origLen >= 0) {
            "Negative orig_len"
        }

        val payload = ByteArray(inclLen)
        readRemaining(input, payload, 0)

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

    fun readAll(): List<PcapPacket> {
        val list = ArrayList<PcapPacket>()
        while (true) {
            val packet = readPacket() ?: break
            list += packet
        }
        return list
    }

    override fun iterator(): Iterator<PcapPacket> {
        return object : Iterator<PcapPacket> {
            private var nextPacket: PcapPacket? = fetch()

            private fun fetch(): PcapPacket? {
                return readPacket()
            }

            override fun hasNext(): Boolean {
                return nextPacket != null
            }

            override fun next(): PcapPacket {
                val current = nextPacket ?: throw NoSuchElementException()
                nextPacket = fetch()
                return current
            }
        }
    }

    override fun close() {
        input.close()
    }

    private fun readRemaining(
        input: InputStream,
        data: ByteArray,
        start: Int
    ) {
        var offset = start
        while (offset < data.size) {
            val read = input.read(data, offset, data.size - offset)
            if (read < 0) {
                throw EOFException()
            }
            offset += read
        }
    }
}
