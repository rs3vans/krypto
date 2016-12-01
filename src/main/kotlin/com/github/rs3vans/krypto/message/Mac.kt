package com.github.rs3vans.krypto.message

import com.github.rs3vans.krypto.key.Key
import javax.crypto.Mac as JdkMac
import java.security.Provider as JdkSecurityProvider

/**
 * A [Mac] is an object used to create a
 * [message authentication code][https://en.wikipedia.org/wiki/Message_authentication_code], which is used to
 * authenticate a piece of data (message) in both authenticity and integrity.
 */
class Mac(val key: Key,
          val algorithm: String = DEFAULT_ALGORITHM,
          val provider: java.security.Provider? = null,
          val providerName: String? = null) {

    val keyAlgorithm: String
        get() = key.algorithm

    private val jdkMac: javax.crypto.Mac

    init {
        jdkMac = if (provider != null) {
            javax.crypto.Mac.getInstance(algorithm, provider)
        } else if (providerName != null) {
            javax.crypto.Mac.getInstance(algorithm, providerName)
        } else {
            javax.crypto.Mac.getInstance(algorithm)
        }
        jdkMac.init(key.jdkSecretKey)
    }

    fun create(data: ByteArray): ByteArray = synchronized(jdkMac) {
        jdkMac.doFinal(data)
    }

    companion object {

        /**
         * The default algorithm used for signing.
         */
        const val DEFAULT_ALGORITHM = "HmacSHA256"
    }
}