package org.krypto

import java.util.*

/**
 * TODO
 */
data class Encrypted(val bytes: ByteArray, val iv: ByteArray) {

    /**
     * TODO
     */
    constructor(bytesWithIV: ByteArray) : this(
            bytesWithIV.copyOfRange(0, bytesWithIV.size - IV_SIZE),
            bytesWithIV.copyOfRange(bytesWithIV.size - IV_SIZE, bytesWithIV.size))

    val bytesWithIV = bytes + iv

    override fun hashCode(): Int = Arrays.hashCode(bytesWithIV)

    override fun equals(other: Any?): Boolean = when (other) {
        is ByteArray -> Arrays.equals(bytesWithIV, other)
        else -> false
    }

    companion object {

        /**
         * TODO
         */
        const val IV_SIZE = 16
    }
}