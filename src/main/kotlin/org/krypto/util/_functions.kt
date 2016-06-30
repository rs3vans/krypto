package org.krypto.util

import java.util.*

const val DEFAULT_RANDOM_BYTES_SIZE = 8

/**
 * Generate an [array][ByteArray] of random bytes (given a size).
 */
fun generateRandomBytes(size: Int = DEFAULT_RANDOM_BYTES_SIZE): ByteArray =
        ByteArray(size).apply { secureRandom.nextBytes(this) }

/**
 * Convert a [ByteArray] into a [Base64-encoded](https://en.wikipedia.org/wiki/Base64) [ByteArray].
 */
fun ByteArray.encodeBase64(): ByteArray = Base64.getEncoder().encode(this)

/**
 * Convert a [ByteArray] into a [Base64-encoded](https://en.wikipedia.org/wiki/Base64) [String].
 */
fun ByteArray.encodeBase64String(): String = Base64.getEncoder().encodeToString(this)

/**
 * Decode a [Base64-encoded](https://en.wikipedia.org/wiki/Base64) [ByteArray].
 */
fun ByteArray.decodeBase64(): ByteArray = Base64.getDecoder().decode(this)

/**
 * Decode a [Base64-encoded](https://en.wikipedia.org/wiki/Base64) [String].
 */
fun String.decodBase64(): ByteArray = Base64.getDecoder().decode(this)