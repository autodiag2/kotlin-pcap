package io.github.autodiag2.kotlin.pcap.packet

class UDP(
    var sourcePort: Int,
    var destinationPort: Int,
    var payload: ByteArray
) : Packet() {

    override fun serialize(): ByteArray {

        val length = 8 + payload.size

        val out = ByteArray(length)

        out[0] = (sourcePort shr 8).toByte()
        out[1] = sourcePort.toByte()

        out[2] = (destinationPort shr 8).toByte()
        out[3] = destinationPort.toByte()

        out[4] = (length shr 8).toByte()
        out[5] = length.toByte()

        System.arraycopy(
            payload,
            0,
            out,
            8,
            payload.size
        )

        return out
    }
}