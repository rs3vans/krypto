package com.github.rs3vans.krypto

import org.hamcrest.CoreMatchers.*
import org.hamcrest.MatcherAssert.assertThat
import org.junit.Test
import java.security.KeyPair
import javax.crypto.*

private const val MESSAGE = "Hello World!"
private const val AUTH_DATA = "foo"

private const val ENCRYPTED_MESSAGE_AES = "gUMO7Rn0qYOVYWeO42QX+w=="
private const val ENCRYPTED_MESSAGE_AAD = "L5qO1MCm5XiIt0Je"
private const val IV = "Akli2l0AR1DwOVGQ4+b4tw=="
private const val AUTH_TAG = "zaVKvwkEEAURR/S9DeR6IA=="

private val key = importAesKey(AES_KEY.toBytesFromBase64())
private val publicKey = importPublicKey(PUBLIC_KEY.toBytesFromBase64())
private val privateKey = importPrivateKey(PRIVATE_KEY.toBytesFromBase64())

class BlockCipherCreateTests {

    @Test
    fun `it should create a padded block cipher`() {
        val cipher = BlockCipher(key)

        assertThat(cipher.algorithm, equalTo("AES/CBC/PKCS5Padding"))
        assertThat(cipher.blockSize, equalTo(16))
    }

    @Test
    fun `it should create an un-padded block cipher`() {
        val cipher = BlockCipher(key, padded = false)

        assertThat(cipher.algorithm, equalTo("AES/CBC/NoPadding"))
    }
}

class BlockCipherEncryptTests {

    private val cipher = BlockCipher(key)

    @Test
    fun `it should encrypt the message`() {
        val encrypted = cipher.encrypt(Decrypted(
                bytes = MESSAGE.toBytes(),
                initVector = IV.toBytesFromBase64()
        ))

        assertThat(encrypted.bytes.toBase64String(), equalTo(ENCRYPTED_MESSAGE_AES))
        assertThat(encrypted.initVector?.toBase64String(), equalTo(IV))
    }

    @Test
    fun `it should encrypt the message with a different init vector`() {
        val encrypted = cipher.encrypt(Decrypted(
                bytes = MESSAGE.toBytes(),
                initVector = Bytes.generateRandomBytes(16)
        ))

        assertThat(encrypted.bytes.toBase64String(), not(equalTo(ENCRYPTED_MESSAGE_AES)))
        assertThat(encrypted.initVector?.toBase64String(), not(equalTo(IV)))
    }

    @Test
    fun `it should encrypt the message with no explicit init vector`() {
        val encrypted = cipher.encrypt(Decrypted(
                bytes = MESSAGE.toBytes()
        ))

        assertThat(encrypted.bytes.toBase64String(), not(equalTo(ENCRYPTED_MESSAGE_AES)))
        assertThat(encrypted.initVector, notNullValue())
    }

    @Test
    fun `it should decrypt the message`() {
        val decrypted = cipher.decrypt(Encrypted(
                bytes = ENCRYPTED_MESSAGE_AES.toBytesFromBase64(),
                initVector = IV.toBytesFromBase64()
        ))

        assertThat(decrypted.bytes.toDecodedString(), equalTo(MESSAGE))
    }

    @Test(expected = BadPaddingException::class)
    fun `it should fail to decrypt the message due to invalid init vector`() {
        cipher.decrypt(Encrypted(
                bytes = ENCRYPTED_MESSAGE_AES.toBytesFromBase64(),
                initVector = Bytes.generateRandomBytes(16)
        ))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `it should fail to decrypt the message due to no init vector`() {
        cipher.decrypt(Encrypted(
                bytes = ENCRYPTED_MESSAGE_AES.toBytesFromBase64()
        ))
    }
}

class AuthenticatingBlockCipherCreateTests {

    @Test
    fun `it should create an authenticating block cipher`() {
        val cipher = AuthenticatingBlockCipher(key)

        assertThat(cipher.algorithm, equalTo("AES/GCM/NoPadding"))
    }
}

class AuthenticatingBlockCipherEncryptTests {

    private val cipher = AuthenticatingBlockCipher(key)

    @Test
    fun `it should encrypt the message with authenticated data`() {
        val encrypted = cipher.encrypt(Decrypted(
                MESSAGE.toBytes(),
                initVector = IV.toBytesFromBase64(),
                additionalAuthenticatedData = AUTH_DATA.toBytesFromBase64()
        ))

        assertThat(encrypted.bytes.toBase64String(), equalTo(ENCRYPTED_MESSAGE_AAD))
        assertThat(encrypted.initVector?.toBase64String(), equalTo(IV))
        assertThat(encrypted.authenticationTag?.toBase64String(), equalTo(AUTH_TAG))
    }

    @Test
    fun `it should decrypt the message with authentication data`() {
        val decrypted = cipher.decrypt(Encrypted(
                ENCRYPTED_MESSAGE_AAD.toBytesFromBase64(),
                initVector = IV.toBytesFromBase64(),
                authenticationTag = AUTH_TAG.toBytesFromBase64(),
                additionalAuthenticatedData = AUTH_DATA.toBytesFromBase64()
        ))

        assertThat(decrypted.bytes.toDecodedString(), equalTo(MESSAGE))
    }

    @Test(expected = AEADBadTagException::class)
    fun `it should fail to decrypt the message with no authentication data`() {
        cipher.decrypt(Encrypted(
                ENCRYPTED_MESSAGE_AAD.toBytesFromBase64(),
                initVector = IV.toBytesFromBase64(),
                authenticationTag = AUTH_TAG.toBytesFromBase64()
        ))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `it should fail to decrypt the message with no authentication tag`() {
        cipher.decrypt(Encrypted(
                ENCRYPTED_MESSAGE_AAD.toBytesFromBase64(),
                initVector = IV.toBytesFromBase64(),
                additionalAuthenticatedData = AUTH_DATA.toBytesFromBase64()
        ))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `it should fail to decrypt the message with no init vector`() {
        cipher.decrypt(Encrypted(
                ENCRYPTED_MESSAGE_AAD.toBytesFromBase64(),
                authenticationTag = AUTH_TAG.toBytesFromBase64(),
                additionalAuthenticatedData = AUTH_DATA.toBytesFromBase64()
        ))
    }
}

class AsymmetricCipherCreateTests {

    @Test
    fun `it should create an asymmetric encrypt cipher`() {
        val cipher = AsymmetricEncryptCipher(publicKey)

        assertThat(cipher.algorithm, equalTo("RSA/ECB/PKCS1Padding"))
    }

    @Test
    fun `it should create an asymmetric decrypt cipher`() {
        val cipher = AsymmetricDecryptCipher(privateKey)

        assertThat(cipher.algorithm, equalTo("RSA/ECB/PKCS1Padding"))
    }

    @Test
    fun `it should create an asymmetric cipher pair`() {
        val cipher = AsymmetricCipherPair(publicKey, privateKey)

        assertThat(cipher.encryptCipher.algorithm, equalTo("RSA/ECB/PKCS1Padding"))
        assertThat(cipher.decryptCipher.algorithm, equalTo("RSA/ECB/PKCS1Padding"))
    }

    @Test
    fun `it should create an asymmetric cipher pair from KeyPair`() {
        val cipher = AsymmetricCipherPair(KeyPair(publicKey, privateKey))

        assertThat(cipher.encryptCipher.algorithm, equalTo("RSA/ECB/PKCS1Padding"))
        assertThat(cipher.decryptCipher.algorithm, equalTo("RSA/ECB/PKCS1Padding"))
    }
}

class AsymmetricCipherEncryptTests {

    private val encryptCipher = AsymmetricEncryptCipher(publicKey)
    private val decryptCipher = AsymmetricDecryptCipher(privateKey)
    private val cipher = AsymmetricCipherPair(publicKey, privateKey)

    @Test
    fun `should encrypt AND decrypt the message`() {
        val encrypted = encryptCipher.encrypt(Decrypted(MESSAGE.toBytes()))
        val decrypted = decryptCipher.decrypt(encrypted)

        assertThat(decrypted.bytes, equalTo(MESSAGE.toBytes()))
    }

    @Test
    fun `should encrypt AND decrypt the message using the cipher pair`() {
        val encrypted = cipher.encrypt(Decrypted(MESSAGE.toBytes()))
        val decrypted = cipher.decrypt(encrypted)

        assertThat(decrypted.bytes, equalTo(MESSAGE.toBytes()))
    }
}