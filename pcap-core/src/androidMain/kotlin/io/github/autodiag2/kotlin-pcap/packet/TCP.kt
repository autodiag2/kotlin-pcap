package io.github.autodiag2.kotlin.pcap.packet

class TCP(
    var sourcePort: Int,
    var destinationPort: Int,
    var sequenceNumber: Long = 0,
    var acknowledgmentNumber: Long = 0,
    var flags: Int = 0x18,
    var windowSize: Int = 65535,
    var payloadData: ByteArray = ByteArray(0)
) : Packet() {

    override fun serialize(): ByteArray {

        val dataOffset = 5
        val headerLength = dataOffset * 4

        val out = ByteArray(
            headerLength + payloadData.size
        )

        out[0] = (sourcePort shr 8).toByte()
        out[1] = sourcePort.toByte()

        out[2] = (destinationPort shr 8).toByte()
        out[3] = destinationPort.toByte()

        out[4] = (sequenceNumber shr 24).toByte()
        out[5] = (sequenceNumber shr 16).toByte()
        out[6] = (sequenceNumber shr 8).toByte()
        out[7] = sequenceNumber.toByte()

        out[8] = (acknowledgmentNumber shr 24).toByte()
        out[9] = (acknowledgmentNumber shr 16).toByte()
        out[10] = (acknowledgmentNumber shr 8).toByte()
        out[11] = acknowledgmentNumber.toByte()

        out[12] = (dataOffset shl 4).toByte()
        out[13] = flags.toByte()

        out[14] = (windowSize shr 8).toByte()
        out[15] = windowSize.toByte()

        System.arraycopy(
            payloadData,
            0,
            out,
            headerLength,
            payloadData.size
        )

        return out
    }
}