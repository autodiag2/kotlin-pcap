@file:Suppress("MemberVisibilityCanBePrivate", "unused")

package io.github.autodiag2.kotlin.pcap

import java.nio.ByteOrder
import io.github.autodiag2.kotlin.pcap.packet.Packet

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
) {

    companion object {

        fun fromPacket(
            header: PcapPacketHeader,
            packet: Packet
        ): PcapPacket {

            return PcapPacket(
                header = header,
                payload = packet.serialize()
            )
        }
    }
}
