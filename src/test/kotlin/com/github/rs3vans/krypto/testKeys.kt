package com.github.rs3vans.krypto

import org.hamcrest.CoreMatchers.*
import org.hamcrest.MatcherAssert.assertThat
import org.junit.Test

class RandomAESKeyTests {

    private val key = generateRandomAesKey()

    @Test
    fun `it should have the AES algorithm`() {
        assertThat(key.algorithm, equalTo("AES"))
    }

    @Test
    fun `it should be 128 bits in size`() {
        assertThat(key.encoded.size, equalTo(128 / 8))
    }

    @Test
    fun `it should never be equal to another random key`() {
        val anotherKey = generateRandomAesKey()
        assertThat(key.toBytes(), not(equalTo(anotherKey.toBytes())))
    }
}

class PasswordDerivedAESKeyTests {

    private val password = "this1sAp@s5w0rD".toCharArray()
    private val salt = Bytes.generateRandomBytes()
    private val key = deriveAesKeyFromPassword(password, salt)

    @Test
    fun `it should have the AES algorithm`() {
        assertThat(key.algorithm, equalTo("AES"))
    }

    @Test
    fun `it should be 128 bits in size`() {
        assertThat(key.encoded.size, equalTo(128 / 8))
    }

    @Test
    fun `it should be reproducible using the same salt`() {
        val anotherKey = deriveAesKeyFromPassword(password, salt)
        assertThat(key.toBytes(), equalTo(anotherKey.toBytes()))
    }

    @Test
    fun `it should never be equal to another key of the same password, but a different salt`() {
        val anotherKey = deriveAesKeyFromPassword(password, Bytes.generateRandomBytes())
        assertThat(key.toBytes(), not(equalTo(anotherKey.toBytes())))
    }
}

class ImportedAESKeyTests {
    @Test
    fun `it should import an AES key from bytes`() {
        val key = importAesKey(AES_KEY.toBytesFromBase64())

        assertThat(key.toBytes().toBase64String(), equalTo(AES_KEY))
    }
}

class AsymmetricKeyTests {

    @Test
    fun `it should generate a random key pair`() {
        val keyPair = generateRandomAsymmetricKeyPair()

        assertThat(keyPair.public.toBytes(), notNullValue())
        assertThat(keyPair.private.toBytes(), notNullValue())
    }

    @Test
    fun `it should import a public key`() {
        val publicKey = importPublicKey(PUBLIC_KEY.toBytesFromBase64())

        assertThat(publicKey.toBytes().toBase64String(), equalTo(PUBLIC_KEY))
    }

    @Test
    fun `it should import a private key`() {
        val privateKey = importPrivateKey(PRIVATE_KEY.toBytesFromBase64())

        assertThat(privateKey.toBytes().toBase64String(), equalTo(PRIVATE_KEY))
    }
}
