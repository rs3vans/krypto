package com.github.rs3vans.krypto

import com.github.rs3vans.krypto.key.PasswordBasedKey
import com.github.rs3vans.krypto.util.DEFAULT_RANDOM_BYTES_SIZE
import com.github.rs3vans.krypto.util.decodeBase64
import com.github.rs3vans.krypto.util.encodeBase64String
import com.github.rs3vans.krypto.util.generateRandomBytes

/**
 * Securely [hash][PasswordBasedKey] a password using the given salt (or a random one), returning a Base64 encoded
 * [String] with an embedded salt.
 */
fun String.hashPassword(salt: ByteArray = generateRandomBytes()): String =
        (PasswordBasedKey(this.toCharArray(), salt = salt).bytes + salt).encodeBase64String()

/**
 * Checks to see if the given [hash] value matches the (re)hashing of this string.
 */
fun String.matchesPasswordHash(hash: String,
                               saltSize: Int = DEFAULT_RANDOM_BYTES_SIZE): Boolean =
        hash == hashPassword(extractSaltFromHash(hash, saltSize))

/**
 * Taking a Base64-encoded [hash] with an embedded salt and a [salt size][saltSize], extract and return the
 * [data bytes][ByteArray].
 */
fun extractDataFromHash(hash: String,
                        saltSize: Int = DEFAULT_RANDOM_BYTES_SIZE): ByteArray =
        with(hash.decodeBase64()) { copyOfRange(0, size - saltSize) }

/**
 * Taking a Base64-encoded [hash] with an embedded salt and a [salt size][saltSize], extract and return the
 * [salt bytes][ByteArray].
 */
fun extractSaltFromHash(hash: String,
                        saltSize: Int = DEFAULT_RANDOM_BYTES_SIZE): ByteArray =
        with(hash.decodeBase64()) { copyOfRange(size - saltSize, size) }