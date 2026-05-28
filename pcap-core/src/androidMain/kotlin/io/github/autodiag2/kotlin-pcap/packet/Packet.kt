package io.github.autodiag2.kotlin.pcap.packet

abstract class Packet {

    abstract fun serialize(): ByteArray
}