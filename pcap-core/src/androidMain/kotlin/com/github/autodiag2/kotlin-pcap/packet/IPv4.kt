package com.github.autodiag2.kotlin.pcap.packet

class IPv4(
    var sourceIp: ByteArray,
    var destinationIp: ByteArray,
    var protocol: Int,
    var ttl: Int = 64,
    var identification: Int = 0,
    var flagsFragment: Int = 0,
    var dscpEcn: Int = 0,
    var payload: Packet? = null
) : Packet() {

    override fun serialize(): ByteArray {
        val payloadBytes = payload?.serialize()
            ?: ByteArray(0)

        val ihl = 5
        val version = 4
        val headerLength = ihl * 4
        val totalLength = headerLength + payloadBytes.size

        val out = ByteArray(totalLength)

        out[0] = ((version shl 4) or ihl).toByte()
        out[1] = dscpEcn.toByte()

        out[2] = (totalLength shr 8).toByte()
        out[3] = totalLength.toByte()

        out[4] = (identification shr 8).toByte()
        out[5] = identification.toByte()

        out[6] = (flagsFragment shr 8).toByte()
        out[7] = flagsFragment.toByte()

        out[8] = ttl.toByte()
        out[9] = protocol.toByte()

        System.arraycopy(sourceIp, 0, out, 12, 4)
        System.arraycopy(destinationIp, 0, out, 16, 4)

        val checksum = checksum(
            out,
            0,
            headerLength
        )

        out[10] = (checksum shr 8).toByte()
        out[11] = checksum.toByte()

        System.arraycopy(
            payloadBytes,
            0,
            out,
            headerLength,
            payloadBytes.size
        )

        return out
    }

    private fun checksum(
        data: ByteArray,
        offset: Int,
        length: Int
    ): Int {

        var sum = 0
        var i = offset

        while (i < offset + length) {
            if (i == 10) {
                i += 2
                continue
            }

            val high = data[i].toInt() and 0xFF
            val low = data[i + 1].toInt() and 0xFF

            sum += (high shl 8) or low

            while (0xFFFF < sum) {
                sum = (sum and 0xFFFF) + (sum shr 16)
            }

            i += 2
        }

        return sum.inv() and 0xFFFF
    }
}