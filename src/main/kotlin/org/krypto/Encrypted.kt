package org.krypto

import java.util.*

/**
 * Represents an encrypted output from a [Cipher].
 */
data class Encrypted(val bytes: ByteArray, val iv: ByteArray) {

    val bytesWithIV = bytes + iv

    override fun hashCode(): Int = Arrays.hashCode(bytesWithIV)

    override fun equals(other: Any?): Boolean = when (other) {
        is ByteArray -> Arrays.equals(bytesWithIV, other)
        else -> false
    }
}