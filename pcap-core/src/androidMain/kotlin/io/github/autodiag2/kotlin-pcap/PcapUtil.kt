package io.github.autodiag2.kotlin.pcap

import kotlin.math.min

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
