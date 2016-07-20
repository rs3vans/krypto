package org.rs3vans.kt.krypto.key

import org.rs3vans.kt.krypto.util.generateRandomBytes
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.security.Provider as JdkSecurityProvider

/**
 * [PasswordBasedKey] represents a [Key] which is
 * [derived from a password](https://en.wikipedia.org/wiki/Key_derivation_function).
 *
 * This implementation uses [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) with a [salt] and number of [iterations].
 *
 * Additionally, a [security provider][java.security.Provider] can be provided for use in deriving the key.
 */
class PasswordBasedKey(password: CharArray,
                       val derivationAlgorithm: String = DEFAULT_DERIVATION_ALGORITHM,
                       val salt: ByteArray = generateRandomBytes(),
                       val iterations: Int = DEFAULT_ITERATIONS,
                       val keyLength: Int = DEFAULT_KEY_LENGTH,
                       val provider: JdkSecurityProvider? = null,
                       val providerName: String? = null) :
        Key(generateSecretKey(password, derivationAlgorithm, salt, iterations, keyLength, provider, providerName)) {

    companion object {

        /**
         * The default [derivation algorithm][derivationAlgorithm] used when none is specified.
         */
        const val DEFAULT_DERIVATION_ALGORITHM = "HmacSHA1"

        /**
         * The default number of [iterations] used when none is specified.
         */
        const val DEFAULT_ITERATIONS = 65536

        /**
         * The default [key length][keyLength] used when none is specified.
         */
        const val DEFAULT_KEY_LENGTH = 128

        private fun generateSecretKey(password: CharArray,
                                      derivationAlgorithm: String,
                                      salt: ByteArray,
                                      iterations: Int,
                                      keyLength: Int,
                                      provider: JdkSecurityProvider?,
                                      providerName: String?): SecretKey {
            val algorithm = "PBKDF2With$derivationAlgorithm"
            val factory = if (provider != null) {
                SecretKeyFactory.getInstance(algorithm, provider)
            } else if (providerName != null) {
                SecretKeyFactory.getInstance(algorithm, providerName)
            } else {
                SecretKeyFactory.getInstance(algorithm)
            }
            val secret = factory.generateSecret(PBEKeySpec(password, salt, iterations, keyLength))
            return SecretKeySpec(secret.encoded, "AES")
        }
    }
}