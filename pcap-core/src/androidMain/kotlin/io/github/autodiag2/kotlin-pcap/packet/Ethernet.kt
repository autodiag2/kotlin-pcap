package io.github.autodiag2.kotlin.pcap.packet

class Ethernet(
    var destinationMac: ByteArray,
    var sourceMac: ByteArray,
    var etherType: Int,
    var payload: Packet? = null
) : Packet() {

    override fun serialize(): ByteArray {
        val payloadBytes = payload?.serialize()
            ?: ByteArray(0)

        val out = ByteArray(14 + payloadBytes.size)

        System.arraycopy(destinationMac, 0, out, 0, 6)
        System.arraycopy(sourceMac, 0, out, 6, 6)

        out[12] = (etherType shr 8).toByte()
        out[13] = etherType.toByte()

        System.arraycopy(
            payloadBytes,
            0,
            out,
            14,
            payloadBytes.size
        )

        return out
    }
}