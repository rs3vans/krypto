package com.github.rs3vans.krypto

import com.github.rs3vans.krypto.KryptoProvider.Companion.defaultInstance
import java.security.*
import java.util.*
import javax.crypto.*

/**
 * A class that encapsulates a JCE provider.
 *
 * @see defaultInstance
 */
class KryptoProvider private constructor(private val providerName: String? = null,
                                         private val provider: Provider? = null) {

    /**
     * Provides an instance of [KeyFactory].
     */
    fun keyFactory(algorithm: String): KeyFactory = provide(
            algorithm,
            KeyFactory::getInstance,
            KeyFactory::getInstance,
            KeyFactory::getInstance
    )

    /**
     * Provides an instance of [SecretKeyFactory].
     */
    fun secretKeyFactory(algorithm: String): SecretKeyFactory = provide(
            algorithm,
            SecretKeyFactory::getInstance,
            SecretKeyFactory::getInstance,
            SecretKeyFactory::getInstance
    )

    /**
     * Provides an instance of [KeyGenerator].
     */
    fun keyGenerator(algorithm: String): KeyGenerator = provide(
            algorithm,
            KeyGenerator::getInstance,
            KeyGenerator::getInstance,
            KeyGenerator::getInstance
    )

    /**
     * Provides an instance of [KeyPairGenerator].
     */
    fun keyPairGenerator(algorithm: String): KeyPairGenerator = provide(
            algorithm,
            KeyPairGenerator::getInstance,
            KeyPairGenerator::getInstance,
            KeyPairGenerator::getInstance
    )

    /**
     * Provides an instance of [Cipher].
     */
    fun cipher(algorithm: String): Cipher = provide(
            algorithm,
            Cipher::getInstance,
            Cipher::getInstance,
            Cipher::getInstance
    )

    /**
     * Provides an instance of [Mac].
     */
    fun mac(algorithm: String): Mac = provide(
            algorithm,
            Mac::getInstance,
            Mac::getInstance,
            Mac::getInstance
    )

    /**
     * Provides an instance of [MessageDigest].
     */
    fun messageDigest(algorithm: String): MessageDigest = provide(
            algorithm,
            MessageDigest::getInstance,
            MessageDigest::getInstance,
            MessageDigest::getInstance
    )

    private inline fun <X> provide(algorithm: String,
                                   defaultFn: (String) -> X,
                                   nameFn: (String, String) -> X,
                                   instanceFn: (String, Provider) -> X): X = if (provider != null) {
        instanceFn.invoke(algorithm, provider)
    } else if (providerName != null) {
        nameFn.invoke(algorithm, providerName)
    } else {
        defaultFn.invoke(algorithm)
    }

    companion object {

        /**
         * An instance of [KryptoProvider] which uses the default JCE provider.
         */
        @JvmStatic
        val defaultInstance = KryptoProvider()

        private val byNameCache = HashMap<String, KryptoProvider>()
        private val byInstanceCache = WeakHashMap<Provider, KryptoProvider>()

        /**
         * Retrieves an instance of [KryptoProvider] for the given provider name.
         */
        fun instanceForProvider(providerName: String): KryptoProvider = synchronized(byNameCache) {
            byNameCache.getOrPut(providerName) {
                KryptoProvider(providerName = providerName)
            }
        }

        /**
         * Retrieves an instance of [KryptoProvider] for the given [Provider].
         */
        fun instanceForProvider(provider: Provider): KryptoProvider = synchronized(byInstanceCache) {
            byInstanceCache.getOrPut(provider) {
                KryptoProvider(provider = provider)
            }
        }
    }
}