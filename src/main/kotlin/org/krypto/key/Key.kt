package org.krypto.key

import javax.crypto.spec.SecretKeySpec

/**
 * [Key] is the base type which represents a key used for encryption/decryption.
 *
 * Every [Key] has an [algorithm] (format), and can be exported as an [array of bytes][bytes].
 *
 * @see org.krypto.Cipher
 */
open class Key internal constructor(val jdkSecretKey: javax.crypto.SecretKey) {

    /**
     * Construct a [Key] from an existing [byte source][bytes], optionally specifying the [algorithm].
     */
    constructor(bytes: ByteArray, algorithm: String = DEFAULT_ALGORITHM) : this(SecretKeySpec(bytes, algorithm))

    val algorithm: String
        get() = jdkSecretKey.algorithm

    val bytes: ByteArray
        get() = jdkSecretKey.encoded

    companion object {

        /**
         * This is the defailt [algorithm] used for creating a [Key] from a [ByteArray] (when none is specified).
         */
        const val DEFAULT_ALGORITHM = "AES"
    }
}