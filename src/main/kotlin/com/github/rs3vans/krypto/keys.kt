@file:JvmName("Keys")

package com.github.rs3vans.krypto

import java.security.*
import java.security.spec.*
import javax.crypto.SecretKey
import javax.crypto.spec.*

private const val AES_KEY_ALGORITHM = "AES"
private const val AES_KEY_SIZE = 128
private const val AES_KEY_BYTE_SIZE = AES_KEY_SIZE / 8

private const val PBE_KEY_ALGORITHM = "PBKDF2WithHmacSHA1"
private const val PBE_KEY_DEFAULT_ITERATIONS = 65536
private const val PBE_KEY_SIZE = 128

private const val ASYM_KEY_ALGORITHM = "RSA"
private const val ASYM_KEY_SIZE = 1024


/**
 * Imports an AES [key][SecretKey] from an instance of [Bytes].
 */
fun importAesKey(bytes: Bytes): SecretKey =
        with(bytes.byteArray) {
            if (size == AES_KEY_BYTE_SIZE) {
                SecretKeySpec(this, AES_KEY_ALGORITHM)
            } else throw IllegalArgumentException(
                    "wrong number of bytes given: $size - (expected $AES_KEY_BYTE_SIZE)"
            )
        }

/**
 * Generates a random AES [key][SecretKey].
 */
fun generateRandomAesKey(random: SecureRandom? = null,
                         provider: KryptoProvider = KryptoProvider.defaultInstance): SecretKey =
        with(provider.keyGenerator(AES_KEY_ALGORITHM)) {
            if (random != null) {
                init(AES_KEY_SIZE, random)
            } else {
                init(AES_KEY_SIZE)
            }
            generateKey()
        }

/**
 * Derives a new AES key from the given password using a strong [PBE-based algorithm][PBE_KEY_ALGORITHM].
 */
fun deriveAesKeyFromPassword(password: CharArray,
                             salt: Bytes,
                             iterations: Int = PBE_KEY_DEFAULT_ITERATIONS,
                             provider: KryptoProvider = KryptoProvider.defaultInstance): SecretKey =
        with(provider.secretKeyFactory(PBE_KEY_ALGORITHM)) {
            SecretKeySpec(
                    generateSecret(PBEKeySpec(
                            password,
                            salt.byteArray,
                            iterations,
                            PBE_KEY_SIZE
                    )).encoded,
                    AES_KEY_ALGORITHM
            )
        }

/**
 * Imports a [RSA-based public key][PublicKey] from an instance of [Bytes].
 */
fun importPublicKey(bytes: Bytes,
                    provider: KryptoProvider = KryptoProvider.defaultInstance): PublicKey =
        provider.keyFactory(ASYM_KEY_ALGORITHM)
                .generatePublic(X509EncodedKeySpec(bytes.byteArray))

/**
 * Imports an [RSA-based private key][PrivateKey] from an instance of [Bytes].
 */
fun importPrivateKey(bytes: Bytes,
                     provider: KryptoProvider = KryptoProvider.defaultInstance): PrivateKey =
        provider.keyFactory(ASYM_KEY_ALGORITHM)
                .generatePrivate(PKCS8EncodedKeySpec(bytes.byteArray))

/**
 * Imports [RSA-based] [public][PublicKey] and [private][PrivateKey] keys as a [pair][KeyPair].
 */
fun importAsymmetricKeyPair(publicBytes: Bytes,
                            privateBytes: Bytes,
                            provider: KryptoProvider = KryptoProvider.defaultInstance): KeyPair =
        KeyPair(
                importPublicKey(publicBytes, provider),
                importPrivateKey(privateBytes, provider)
        )

/**
 * Generates a random [KeyPair] for asymmetric (RSA-based) encryption/decryption.
 */
fun generateRandomAsymmetricKeyPair(random: SecureRandom? = null,
                                    provider: KryptoProvider = KryptoProvider.defaultInstance): KeyPair =
        with(provider.keyPairGenerator(ASYM_KEY_ALGORITHM)) {
            if (random != null) {
                initialize(ASYM_KEY_SIZE, random)
            } else {
                initialize(ASYM_KEY_SIZE)
            }
            genKeyPair()
        }