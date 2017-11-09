@file:JvmName("ToBytes")

package com.github.rs3vans.krypto

import java.io.*
import java.nio.ByteBuffer
import java.nio.charset.Charset
import java.security.*
import java.util.*

/**
 * A class that wraps a [ByteArray], providing ease-of-use and additional functionality.
 */
class Bytes(val byteArray: ByteArray) {

    val size: Int get() = byteArray.size

    /**
     * Convert a [Bytes] into a [Base64-encoded](https://en.wikipedia.org/wiki/Base64) [String].
     */
    fun toBase64String(): String = Base64.getEncoder().encodeToString(byteArray)

    /**
     * Convert a [Bytes] into a Hex-encoded [String].
     */
    fun toHexString(): String {
        val hexChars = CharArray(byteArray.size * 2)
        for (i in byteArray.indices) {
            val b = byteArray[i].toInt()
            val j = i * 2
            hexChars[j] = hexArray[b.ushr(4) and 0xF]
            hexChars[j + 1] = hexArray[b and 0xF]
        }
        return String(hexChars)
    }

    /**
     * Convert a [Bytes] into a [ByteBuffer].
     */
    fun toByteBuffer(): ByteBuffer = ByteBuffer.wrap(byteArray)

    /**
     * Convert a [Bytes] into a String by decoding it using the given [Charset], assuming it contains character data.
     */
    fun toDecodedString(charset: Charset = Charsets.UTF_8): String = String(byteArray, charset)

    /**
     * Convert a [Bytes] into an [InputStream].
     */
    fun toInputStream(): InputStream = ByteArrayInputStream(byteArray)

    /**
     * Convert a [Bytes] into a [T] by deserializing it using an [ObjectInputStream].
     *
     * Will cause a [ClassCastException] if [byteArray] doesn't contained the serialized form of an instance of [T].
     */
    fun <T : Serializable> deserializeToObject(): T {
        return ObjectInputStream(toInputStream()).use {
            @Suppress("UNCHECKED_CAST")
            it.readObject() as T
        }
    }

    /**
     * Create a new [Bytes] that is [byteArray] with [other.byteArray][other] appended directly after.
     */
    operator fun plus(other: Bytes): Bytes = Bytes(Arrays.copyOf(byteArray, size + other.size).apply {
        System.arraycopy(other.byteArray, 0, this, this@Bytes.size, other.size)
    })

    /**
     * Creates a _deep_ copy of this [Bytes], where the new instance's [byteArray] is an entirely new [ByteArray] with
     * each byte copied by value.
     */
    fun copy(): Bytes = Bytes(Arrays.copyOf(byteArray, size))

    /**
     * Creates a _deep_ copy of this [Bytes], where the new instance's [byteArray] is an entirely new [ByteArray] with
     * each byte within [range] copied by value.
     */
    fun copyOfRange(range: IntRange): Bytes = Bytes(Arrays.copyOfRange(byteArray, range.first, range.last))

    override fun equals(other: Any?): Boolean = other is Bytes && Arrays.equals(byteArray, other.byteArray)
    override fun hashCode(): Int = Arrays.hashCode(byteArray)
    override fun toString(): String = toBase64String()

    companion object {

        const val DEFAULT_RANDOM_BYTES_SIZE = 8

        private val hexArray = "0123456789ABCDEF".toCharArray()
        private val secureRandom = SecureRandom()

        /**
         * Generate random [Bytes] of a given size.
         */
        @JvmStatic
        @JvmOverloads
        fun generateRandomBytes(size: Int = DEFAULT_RANDOM_BYTES_SIZE): Bytes =
                ByteArray(size).apply { secureRandom.nextBytes(this) }.toBytes()
    }
}

/**
 * Extension function that converts a [ByteArray] to an instance of [Bytes].
 *
 * The new instance of [Bytes] wraps the original [ByteArray].
 */
fun ByteArray.toBytes(): Bytes = Bytes(this)

/**
 * Extension function that converts a [ByteBuffer] to an instance of [Bytes].
 */
fun ByteBuffer.toBytes(): Bytes = array().toBytes()

/**
 * Extension function that converts (encodes) a [CharSequence] to an instance of [Bytes] using the given [charset].
 */
@JvmOverloads
fun CharSequence.toBytes(charset: Charset = Charsets.UTF_8): Bytes = toString().toByteArray(charset).toBytes()

/**
 * Decode a [Base64-encoded](https://en.wikipedia.org/wiki/Base64) [String] to a [Bytes].
 */
fun CharSequence.toBytesFromBase64() = Base64.getDecoder().decode(toString()).toBytes()

/**
 * Decode a Hex-encoded [String] to a [Bytes].
 */
fun CharSequence.toBytesFromHex(): Bytes {
    val data = ByteArray(length / 2)
    var i = 0
    while (i < length) {
        data[i / 2] = ((Character.digit(this[i], 16) shl 4) + Character.digit(this[i + 1], 16)).toByte()
        i += 2
    }
    return Bytes(data)
}

/**
 * Extension function that converts an [InputStream] to an instance of [Bytes].
 */
fun InputStream.toBytes(): Bytes = readBytes().toBytes()

/**
 * Extension function that serializes any [Serializable] to an instance of [Bytes] using an [ObjectOutputStream].
 */
fun Serializable.serializeToBytes(): Bytes {
    val bos = ByteArrayOutputStream()
    ObjectOutputStream(bos).use {
        it.writeObject(this)
    }
    return bos.toByteArray().toBytes()
}

/**
 * Extension function that converts a [Key] to an instance of [Bytes].
 *
 * @see Key.getEncoded
 */
fun Key.toBytes(): Bytes = encoded.toBytes()