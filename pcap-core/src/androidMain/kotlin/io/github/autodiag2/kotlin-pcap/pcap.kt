@file:Suppress("MemberVisibilityCanBePrivate", "unused")

package io.github.autodiag2.kotlin.pcap

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.Closeable
import java.io.DataInputStream
import java.io.EOFException
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import kotlin.math.min

enum class PcapByteOrder {
    BIG_ENDIAN,
    LITTLE_ENDIAN
}

enum class PcapTimestampPrecision {
    MICRO,
    NANO
}

object PcapMagic {
    const val MICRO_BIG = 0xA1B2C3D4.toInt()
    const val MICRO_LITTLE = 0xD4C3B2A1.toInt()
    const val NANO_BIG = 0xA1B23C4D.toInt()
    const val NANO_LITTLE = 0x4D3CB2A1.toInt()
}

object PcapLinkType {
    const val NULL = 0
    const val ETHERNET = 1
    const val AX25 = 3
    const val IEEE802_5 = 6
    const val ARCNET_BSD = 7
    const val SLIP = 8
    const val PPP = 9
    const val FDDI = 10
    const val PPP_HDLC = 50
    const val PPP_ETHER = 51
    const val ATM_RFC1483 = 100
    const val RAW = 101
    const val C_HDLC = 104
    const val IEEE802_11 = 105
    const val FRELAY = 107
    const val LOOP = 108
    const val LINUX_SLL = 113
    const val LTALK = 114
    const val PFLOG = 117
    const val IEEE802_11_PRISM = 119
    const val IP_OVER_FC = 122
    const val SUNATM = 123
    const val IEEE802_11_RADIOTAP = 127
    const val ARCNET_LINUX = 129
    const val APPLE_IP_OVER_IEEE1394 = 138
    const val MTP2_WITH_PHDR = 139
    const val MTP2 = 140
    const val MTP3 = 141
    const val SCCP = 142
    const val DOCSIS = 143
    const val LINUX_IRDA = 144
    const val USER0 = 147
    const val USER15 = 162
    const val IEEE802_11_AVS = 163
    const val BACNET_MS_TP = 165
    const val PPP_PPPD = 166
    const val GPRS_LLC = 169
    const val GPF_T = 170
    const val GPF_F = 171
    const val LINUX_LAPD = 177
    const val BLUETOOTH_HCI_H4 = 187
    const val USB_LINUX = 189
    const val PPI = 192
    const val IEEE802_15_4 = 195
    const val SITA = 196
    const val ERF = 197
    const val BLUETOOTH_HCI_H4_WITH_PHDR = 201
    const val AX25_KISS = 202
    const val LAPD = 203
    const val PPP_WITH_DIR = 204
    const val C_HDLC_WITH_DIR = 205
    const val FRELAY_WITH_DIR = 206
    const val IPMB_LINUX = 209
    const val IEEE802_15_4_NONASK_PHY = 215
    const val USB_LINUX_MMAPPED = 220
    const val FC_2 = 224
    const val FC_2_WITH_FRAME_DELIMS = 225
    const val IPNET = 226
    const val CAN_SOCKETCAN = 227
    const val IPV4 = 228
    const val IPV6 = 229
    const val IEEE802_15_4_NOFCS = 230
    const val DBUS = 231
    const val DVB_CI = 235
    const val MUX27010 = 236
    const val STANAG_5066_D_PDU = 237
    const val NFLOG = 239
    const val NETANALYZER = 240
    const val NETANALYZER_TRANSPARENT = 241
    const val IPOIB = 242
    const val MPEG_2_TS = 243
    const val NG40 = 244
    const val NFC_LLCP = 245
    const val INFINIBAND = 247
    const val SCTP = 248
    const val USBPCAP = 249
    const val RTAC_SERIAL = 250
    const val BLUETOOTH_LE_LL = 251
    const val NETLINK = 253
    const val BLUETOOTH_LINUX_MONITOR = 254
    const val BLUETOOTH_BREDR_BB = 255
    const val BLUETOOTH_LE_LL_WITH_PHDR = 256
    const val PROFIBUS_DL = 257
    const val PKTAP = 258
    const val EPON = 259
    const val IPMI_HPM_2 = 260
    const val ZWAVE_R1_R2 = 261
    const val ZWAVE_R3 = 262
    const val WATTSTOPPER_DLM = 263
    const val ISO_14443 = 264
}

data class PcapGlobalHeader(
    val magic: Int,
    val versionMajor: Int = 2,
    val versionMinor: Int = 4,
    val thisZone: Int = 0,
    val sigFigs: Int = 0,
    val snapLen: Int = 65535,
    val network: Int = PcapLinkType.ETHERNET
) {
    val byteOrder: PcapByteOrder
        get() = when (magic) {
            PcapMagic.MICRO_BIG,
            PcapMagic.NANO_BIG -> PcapByteOrder.BIG_ENDIAN

            else -> PcapByteOrder.LITTLE_ENDIAN
        }

    val precision: PcapTimestampPrecision
        get() = when (magic) {
            PcapMagic.NANO_BIG,
            PcapMagic.NANO_LITTLE -> PcapTimestampPrecision.NANO

            else -> PcapTimestampPrecision.MICRO
        }
}

data class PcapPacketHeader(
    val timestampSeconds: Long,
    val timestampSubseconds: Long,
    val capturedLength: Int,
    val originalLength: Int
)

data class PcapPacket(
    val header: PcapPacketHeader,
    val payload: ByteArray
)

class PcapReader private constructor(
    private val input: InputStream,
    val globalHeader: PcapGlobalHeader
) : Closeable, Iterable<PcapPacket> {

    private val endian = globalHeader.byteOrder

    companion object {

        fun fromFile(file: File): PcapReader {
            return fromInputStream(file.inputStream())
        }

        fun fromPath(path: Path): PcapReader {
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
            file: File,
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

object PcapUtil {

    fun createMicroHeader(
        byteOrder: PcapByteOrder = PcapByteOrder.LITTLE_ENDIAN,
        snapLen: Int = 65535,
        network: Int = PcapLinkType.ETHERNET
    ): PcapGlobalHeader {
        return PcapGlobalHeader(
            magic = when (byteOrder) {
                PcapByteOrder.BIG_ENDIAN -> PcapMagic.MICRO_BIG
                PcapByteOrder.LITTLE_ENDIAN -> PcapMagic.MICRO_LITTLE
            },
            snapLen = snapLen,
            network = network
        )
    }

    fun createNanoHeader(
        byteOrder: PcapByteOrder = PcapByteOrder.LITTLE_ENDIAN,
        snapLen: Int = 65535,
        network: Int = PcapLinkType.ETHERNET
    ): PcapGlobalHeader {
        return PcapGlobalHeader(
            magic = when (byteOrder) {
                PcapByteOrder.BIG_ENDIAN -> PcapMagic.NANO_BIG
                PcapByteOrder.LITTLE_ENDIAN -> PcapMagic.NANO_LITTLE
            },
            snapLen = snapLen,
            network = network
        )
    }

    fun hex(data: ByteArray): String {
        val out = StringBuilder(data.size * 2)

        for (b in data) {
            out.append("%02X".format(b))
        }

        return out.toString()
    }

    fun parseHex(hex: String): ByteArray {
        require(hex.length % 2 == 0)

        val out = ByteArray(hex.length / 2)

        var i = 0

        while (i < hex.length) {
            out[i / 2] = hex.substring(i, i + 2)
                .toInt(16)
                .toByte()

            i += 2
        }

        return out
    }

    fun truncatePayload(
        payload: ByteArray,
        snapLen: Int
    ): ByteArray {
        if (payload.size <= snapLen) {
            return payload
        }

        return payload.copyOf(min(payload.size, snapLen))
    }
}