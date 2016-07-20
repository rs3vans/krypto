package org.rs3vans.kt.krypto.key

import org.rs3vans.kt.krypto.key.RandomKey.generate
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import java.security.Provider as JdkSecurityProvider

/**
 * [RandomKey] facilitates the generation of secure, random [Keys][Key].
 *
 * @see [generate]
 */
object RandomKey {

    /**
     * The default algorithm used for key [generation][generate].
     */
    const val DEFAULT_ALGORITHM = "AES"

    /**
     * The default key size used for key [generation][generate].
     */
    const val DEFAULT_SIZE = 128

    /**
     * Generate a secure, random [Key].
     *
     * Additionally, a [security provider][java.security.Provider] can be provided for use in generating the key.
     */
    fun generate(algorithm: String = DEFAULT_ALGORITHM,
                 size: Int = DEFAULT_SIZE,
                 random: SecureRandom? = null,
                 provider: JdkSecurityProvider? = null,
                 providerName: String? = null): Key {
        val generator = if (provider != null) {
            KeyGenerator.getInstance(algorithm, provider)
        } else if (providerName != null) {
            KeyGenerator.getInstance(algorithm, providerName)
        } else {
            KeyGenerator.getInstance(algorithm)
        }
        return with(generator) {
            if (random == null) {
                init(size)
            } else {
                init(size, random)
            }
            Key(generateKey())
        }
    }
}