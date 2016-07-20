package org.rs3vans.kt.krypto

import org.rs3vans.kt.krypto.key.PasswordBasedKey
import org.rs3vans.kt.krypto.util.DEFAULT_RANDOM_BYTES_SIZE
import org.rs3vans.kt.krypto.util.decodBase64
import org.rs3vans.kt.krypto.util.encodeBase64String
import org.rs3vans.kt.krypto.util.generateRandomBytes

/**
 * Securely [hash][PasswordBasedKey] a password using the given salt (or a random one), returning a Base64 encoded
 * [String] containing both the hash and then the salt.
 */
fun String.hashPassword(salt: ByteArray = generateRandomBytes()): String =
        (PasswordBasedKey(this.toCharArray(), salt = salt).bytes + salt).encodeBase64String()

/**
 * Checks to see if the given [hash] value matches the hashing of this string.
 */
fun String.matchesPasswordHash(hash: String, saltSize: Int = DEFAULT_RANDOM_BYTES_SIZE): Boolean {
    val hashBytes = hash.decodBase64()
    val salt = hashBytes.copyOfRange(hashBytes.size - saltSize, hashBytes.size)

    val newHash = hashPassword(salt)

    return newHash == hash
}