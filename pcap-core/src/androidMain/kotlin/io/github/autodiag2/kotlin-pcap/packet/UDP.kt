package io.github.autodiag2.kotlin.pcap.packet

class UDP(
    var sourcePort: Int,
    var destinationPort: Int,
    var payloadData: ByteArray
) : Packet() {

    override fun serialize(): ByteArray {

        val length = 8 + payloadData.size

        val out = ByteArray(length)

        out[0] = (sourcePort shr 8).toByte()
        out[1] = sourcePort.toByte()

        out[2] = (destinationPort shr 8).toByte()
        out[3] = destinationPort.toByte()

        out[4] = (length shr 8).toByte()
        out[5] = length.toByte()

        System.arraycopy(
            payloadData,
            0,
            out,
            8,
            payloadData.size
        )

        return out
    }
}