package org.krypto

import org.krypto.key.PasswordBasedKey
import org.krypto.util.encodeBase64String
import org.krypto.util.generateRandomBytes

/**
 * Securely [hash][PasswordBasedKey] a password using the given salt (or a random one), returning a Base64 encoded
 * [String] containing both the hash and then the salt.
 */
fun String.hashPassword(salt: ByteArray = generateRandomBytes()): String =
        (PasswordBasedKey(this.toCharArray(), salt = salt).bytes + salt).encodeBase64String()