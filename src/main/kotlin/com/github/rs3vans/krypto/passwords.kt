@file:JvmName("Passwords")

package com.github.rs3vans.krypto

import com.github.rs3vans.krypto.Bytes.Companion.DEFAULT_RANDOM_BYTES_SIZE
import com.github.rs3vans.krypto.Bytes.Companion.generateRandomBytes

/**
 * Securely [hash][PasswordBasedKey] a password using the given salt (or a random one), returning a Base64 encoded
 * [String] with an embedded salt.
 */
@JvmOverloads
fun hashPassword(password: String,
                 salt: Bytes = generateRandomBytes()): String =
        (deriveAesKeyFromPassword(password.toCharArray(), salt = salt).toBytes() + salt).toBase64String()

/**
 * Checks to see if the given [hash] value matches the (re)hashing of this string.
 */
@JvmOverloads
fun matchesPasswordHash(password: String,
                        hash: String,
                        saltSize: Int = DEFAULT_RANDOM_BYTES_SIZE): Boolean =
        hash == hashPassword(password, hash.extractSalt(saltSize))

private fun String.extractSalt(saltSize: Int = DEFAULT_RANDOM_BYTES_SIZE): Bytes =
        with(this.toBytesFromBase64()) { copyOfRange((size - saltSize)..size) }