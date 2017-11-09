package com.github.rs3vans.krypto

import java.security.MessageDigest
import javax.crypto.*

/**
 * Some common algorithms used when creating an HMAC digest.
 */
object HmacAlgorithms {
    const val SHA_256 = "HmacSHA256"
    const val SHA_1 = "HmacSHA1"
    const val MD5 = "HmacMD5"
}

/**
 * Some common algorithms used when creating a one-way hash digest.
 */
object HashAlgorithms {
    const val SHA_256 = "SHA-256"
    const val SHA_1 = "SHA-1"
    const val MD5 = "MD5"
}

/**
 * A base class which describes an object that can one-way digest a message (some data).
 */
abstract class Digester {

    /**
     * The algorithm this [Digester] uses.
     */
    abstract val algorithm: String

    /**
     * The [provider][KryptoProvider] this [Digester] uses.
     */
    abstract val provider: KryptoProvider

    /**
     * Return an instance of [DigestBuilder] fueled by this [Digester].
     */
    abstract fun digestBuilder(): DigestBuilder

    /**
     * Digest the given [Bytes].
     */
    fun digest(bytes: Bytes): Bytes = digestBuilder().update(bytes).digest()

    /**
     * Digest the given sets of [Bytes] as one message.
     */
    fun digest(vararg bytes: Bytes): Bytes = digestBuilder().also { builder ->
        bytes.forEach { builder.update(it) }
    }.digest()
}

/**
 * A builder-style contract for digesting a message.
 */
interface DigestBuilder {

    /**
     * Update the current digest with the given [Bytes].
     *
     * @see digest
     */
    fun update(bytes: Bytes): DigestBuilder

    /**
     * Create a [Bytes] from the digested data contained in this [DigestBuilder] so far.
     *
     * @see update
     */
    fun digest(): Bytes
}

/**
 * A [Digester] implementation which uses HMAC.
 *
 * @see Mac
 */
class HmacDigester @JvmOverloads constructor(val key: SecretKey,
                                             override val algorithm: String = HmacAlgorithms.SHA_256,
                                             override val provider: KryptoProvider = KryptoProvider.defaultInstance) :
        Digester() {

    val jdkMac: Mac = provider.mac(algorithm).apply {
        init(key)
    }

    override fun digestBuilder(): DigestBuilder = MacDigestBuilder()

    private inner class MacDigestBuilder : DigestBuilder {

        init {
            jdkMac.reset()
        }

        override fun update(bytes: Bytes) = apply { jdkMac.update(bytes.byteArray) }

        override fun digest() = jdkMac.doFinal().toBytes()
    }
}

/**
 * A [Digester] implementation that uses a straight-forward hash.
 *
 * @see MessageDigest
 */
class HashDigester @JvmOverloads constructor(override val algorithm: String = HashAlgorithms.SHA_256,
                                             override val provider: KryptoProvider = KryptoProvider.defaultInstance) :
        Digester() {

    val jdkMessageDigest: MessageDigest = provider.messageDigest(algorithm)

    override fun digestBuilder(): DigestBuilder = HashDigestBuilder()

    private inner class HashDigestBuilder : DigestBuilder {

        init {
            jdkMessageDigest.reset()
        }

        override fun update(bytes: Bytes) = apply { jdkMessageDigest.update(bytes.byteArray) }

        override fun digest() = jdkMessageDigest.digest().toBytes()
    }
}
