package com.github.rs3vans.krypto

import com.github.rs3vans.krypto.key.Key
import javax.crypto.spec.IvParameterSpec
import java.security.Provider as JdkSecurityProvider
import javax.crypto.Cipher as JdkCipher

/**
 * A [Cipher] is used to [encrypt] and [decrypt] [binary][ByteArray] data using...
 * - a [Key]
 * - an [algorithm]
 * - a [block cipher mode][mode] (see [here](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation))
 * - a [padding mode][padding] (see [here](https://en.wikipedia.org/wiki/Padding_(cryptography))
 * - optionally a [security provider][provider]
 *
 * Note: Encryptions are randomized using an
 *       [initialization vector](https://en.wikipedia.org/wiki/Initialization_vector) (IV).
 *
 * @see Encrypted
 */
class Cipher(val key: Key,
             val algorithm: String = DEFAULT_ALGORITHM,
             val mode: String = DEFAULT_MODE,
             val padding: String = DEFAULT_PADDING,
             val provider: java.security.Provider? = null,
             val providerName: String? = null) {

    val keyAlgorithm: String
        get() = key.algorithm

    private val jdkEncryptCipher: javax.crypto.Cipher
    private val jdkDecryptCipher: javax.crypto.Cipher

    init {
        val jdkCipherAlgorithm = "$algorithm/$mode/$padding"

        fun createJdkCipher() = if (provider != null) {
            javax.crypto.Cipher.getInstance(jdkCipherAlgorithm, provider)
        } else if (providerName != null) {
            javax.crypto.Cipher.getInstance(jdkCipherAlgorithm, providerName)
        } else {
            javax.crypto.Cipher.getInstance(jdkCipherAlgorithm)
        }

        jdkEncryptCipher = createJdkCipher()
        jdkDecryptCipher = createJdkCipher()
    }

    /**
     * Encrypt the [data], optionally giving an [initialization vector][iv].
     *
     * @see Encrypted
     */
    fun encrypt(data: ByteArray, iv: ByteArray? = null): Encrypted {
        return with(jdkEncryptCipher) {
            synchronized(this) {
                if (iv == null) {
                    init(javax.crypto.Cipher.ENCRYPT_MODE, key.jdkSecretKey)
                } else {
                    init(javax.crypto.Cipher.ENCRYPT_MODE, key.jdkSecretKey, IvParameterSpec(iv))
                }
                Encrypted(doFinal(data), this.iv)
            }
        }
    }

    /**
     * Decrypt the [data][encrypted].
     *
     * @see Encrypted
     */
    fun decrypt(encrypted: Encrypted): ByteArray {
        return with(jdkDecryptCipher) {
            synchronized(this) {
                init(javax.crypto.Cipher.DECRYPT_MODE, key.jdkSecretKey, IvParameterSpec(encrypted.iv))
                doFinal(encrypted.bytes, 0, encrypted.bytes.size)
            }
        }
    }

    companion object {

        /**
         * The default algorithm used for encryption.
         */
        const val DEFAULT_ALGORITHM = "AES"

        /**
         * The default block cipher mode.
         */
        const val DEFAULT_MODE = "CBC"

        /**
         * The default padding mode.
         */
        const val DEFAULT_PADDING = "PKCS5Padding"
    }
}