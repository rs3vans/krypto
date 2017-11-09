package com.github.rs3vans.krypto

import java.security.*
import javax.crypto.*
import javax.crypto.Cipher.*
import javax.crypto.spec.*

/**
 * A simple base class that defines a cipher which wraps an instance [Cipher] along with a [Key].
 */
abstract class ConcreteCipher {

    abstract val jdkCipher: Cipher
    abstract val key: Key
    abstract val provider: KryptoProvider

    val algorithm: String
        get() = jdkCipher.algorithm
    val blockSize: Int
        get() = jdkCipher.blockSize

    protected inline fun <X> withCipher(action: Cipher.() -> X): X = synchronized(jdkCipher) {
        action.invoke(jdkCipher)
    }
}

/**
 * Represents data that is _not_ encrypted (and may have been the result of a [decryption][DecryptCipher.decrypt]).
 */
data class Decrypted(val bytes: Bytes,
                     val initVector: Bytes? = null,
                     val additionalAuthenticatedData: Bytes? = null)

/**
 * Represents data that _is_ encrypted (and may have been the result of an [encryption][EncryptCipher.encrypt]).
 */
data class Encrypted(val bytes: Bytes,
                     val initVector: Bytes? = null,
                     val authenticationTag: Bytes? = null,
                     val additionalAuthenticatedData: Bytes? = null)

/**
 * A contract for a cipher that can [encrypt] an instance of [Decrypted], producing an instance of [Encrypted].
 */
interface EncryptCipher {
    fun encrypt(decrypted: Decrypted): Encrypted
}

/**
 * A contract for a cipher that can [decrypt] an instance of [Encrypted], producing an instance of [Decrypted].
 */
interface DecryptCipher {
    fun decrypt(encrypted: Encrypted): Decrypted
}

/**
 * An [encrypting][EncryptCipher]/[decrypting][DecryptCipher] cipher which uses the chained-block mode (CBC).
 */
class BlockCipher(override val key: SecretKey,
                  padded: Boolean = true,
                  override val provider: KryptoProvider = KryptoProvider.defaultInstance) :
        ConcreteCipher(),
        EncryptCipher,
        DecryptCipher {

    override val jdkCipher = provider.cipher("${key.algorithm}/CBC/${if (padded) "PKCS5Padding" else "NoPadding"}")

    override fun encrypt(decrypted: Decrypted): Encrypted = withCipher {
        if (decrypted.initVector != null) {
            init(ENCRYPT_MODE, key, IvParameterSpec(decrypted.initVector.byteArray))
        } else {
            init(ENCRYPT_MODE, key)
        }
        Encrypted(
                Bytes(doFinal(decrypted.bytes.byteArray)),
                initVector = Bytes(iv)
        )
    }

    override fun decrypt(encrypted: Encrypted): Decrypted = withCipher {
        val iv = encrypted.initVector ?: throw IllegalArgumentException(
                "initialization vector (IV) required for decryption"
        )
        init(DECRYPT_MODE, key, IvParameterSpec(iv.byteArray))
        Decrypted(Bytes(doFinal(encrypted.bytes.byteArray)))
    }
}

/**
 * An [encrypting][EncryptCipher]/[decrypting][DecryptCipher] cipher which uses the Galois-counter mode (GCM).
 */
class AuthenticatingBlockCipher(override val key: SecretKey,
                                override val provider: KryptoProvider = KryptoProvider.defaultInstance) :
        ConcreteCipher(),
        EncryptCipher,
        DecryptCipher {

    override val jdkCipher = provider.cipher("${key.algorithm}/GCM/NoPadding")

    override fun encrypt(decrypted: Decrypted): Encrypted = withCipher {
        if (decrypted.initVector != null) {
            init(ENCRYPT_MODE, key, GCMParameterSpec(blockSize * 8, decrypted.initVector.byteArray))
        } else {
            init(ENCRYPT_MODE, key)
        }
        if (decrypted.additionalAuthenticatedData != null) {
            updateAAD(decrypted.additionalAuthenticatedData.byteArray)
        }
        val encBytes = doFinal(decrypted.bytes.byteArray)
        val tagOffset = encBytes.size - blockSize
        Encrypted(
                Bytes(encBytes.copyOfRange(0, tagOffset)),
                initVector = Bytes(iv),
                authenticationTag = Bytes(encBytes.copyOfRange(tagOffset, encBytes.size))
        )
    }

    override fun decrypt(encrypted: Encrypted): Decrypted = withCipher {
        val iv = encrypted.initVector ?: throw IllegalArgumentException(
                "initialization vector (IV) required for decryption"
        )
        val tag = encrypted.authenticationTag ?: throw IllegalArgumentException(
                "authentication tag required for decryption"
        )
        init(DECRYPT_MODE, key, GCMParameterSpec(blockSize * 8, iv.byteArray))
        if (encrypted.additionalAuthenticatedData != null) {
            updateAAD(encrypted.additionalAuthenticatedData.byteArray)
        }
        Decrypted(Bytes(doFinal(encrypted.bytes.byteArray + tag.byteArray)))
    }
}

/**
 * An [encrypting-only][EncryptCipher] cipher which uses an RSA-based [PublicKey] for encryption.
 */
class AsymmetricEncryptCipher(override val key: PublicKey,
                              override val provider: KryptoProvider = KryptoProvider.defaultInstance) :
        ConcreteCipher(),
        EncryptCipher {

    init {
        if (key.algorithm != "RSA") {
            throw IllegalArgumentException("invalid key algorithm: ${key.algorithm} (expected: RSA)")
        }
    }

    override val jdkCipher = provider.cipher("RSA/ECB/PKCS1Padding")

    override fun encrypt(decrypted: Decrypted): Encrypted = withCipher {
        init(ENCRYPT_MODE, key)
        Encrypted(Bytes(doFinal(decrypted.bytes.byteArray)))
    }
}

/**
 * An [decrypting-only][DecryptCipher] cipher which uses an RSA-based [PrivateKey] for decryption.
 */
class AsymmetricDecryptCipher(override val key: PrivateKey,
                              override val provider: KryptoProvider = KryptoProvider.defaultInstance) :
        ConcreteCipher(),
        DecryptCipher {

    init {
        if (key.algorithm != "RSA") {
            throw IllegalArgumentException("invalid key algorithm: ${key.algorithm} (expected: RSA)")
        }
    }

    override val jdkCipher = provider.cipher("RSA/ECB/PKCS1Padding")

    override fun decrypt(encrypted: Encrypted): Decrypted = withCipher {
        init(DECRYPT_MODE, key)
        Decrypted(Bytes(doFinal(encrypted.bytes.byteArray)))
    }
}

/**
 * An [encrypting][EncryptCipher]/[decrypting][DecryptCipher] cipher which wraps both an [AsymmetricEncryptCipher] and
 * a [AsymmetricDecryptCipher].
 */
class AsymmetricCipherPair(val encryptCipher: AsymmetricEncryptCipher,
                           val decryptCipher: AsymmetricDecryptCipher) :
        EncryptCipher by encryptCipher,
        DecryptCipher by decryptCipher {

    constructor(publicKey: PublicKey,
                privateKey: PrivateKey,
                provider: KryptoProvider = KryptoProvider.defaultInstance) : this(
            AsymmetricEncryptCipher(publicKey, provider),
            AsymmetricDecryptCipher(privateKey, provider)
    )

    constructor(keyPair: KeyPair,
                provider: KryptoProvider = KryptoProvider.defaultInstance) : this(
            keyPair.public,
            keyPair.private,
            provider
    )
}