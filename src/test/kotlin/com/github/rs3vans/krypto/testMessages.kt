package com.github.rs3vans.krypto

import org.hamcrest.CoreMatchers.equalTo
import org.hamcrest.MatcherAssert.assertThat
import org.junit.Test

private const val HMAC_KEY = "itjy6ug21s7YAcUAC5a/+g=="

private const val MESSAGE = "Hello World!"
private const val MESSAGE_PART_A = "Hello "
private const val MESSAGE_PART_B = "World!"

private const val HMAC_MESSAGE = "3aZ8watUQFJj5ViEJQlt7RUi4C8+ItnHkduwbt3W558="
private const val SHA256_MESSAGE = "f4OxZX/x/FO5LcGBSKHWXfwtSx+j1ncoSt3SABJtkGk="

private val key = importAesKey(HMAC_KEY.toBytesFromBase64())

class HmacCreateTests {

    @Test
    fun `it should create a SHA-256 HMAC digester from the given key`() {
        val digester = HmacDigester(key)

        assertThat(digester.algorithm, equalTo(HmacAlgorithms.SHA_256))
    }

    @Test
    fun `it should create a SHA-1 HMAC digester from the given key`() {
        val digester = HmacDigester(key, algorithm = HmacAlgorithms.SHA_1)

        assertThat(digester.algorithm, equalTo(HmacAlgorithms.SHA_1))
    }

    @Test
    fun `it should create a MD5 HMAC digester from the given key`() {
        val digester = HmacDigester(key, algorithm = HmacAlgorithms.MD5)

        assertThat(digester.algorithm, equalTo(HmacAlgorithms.MD5))
    }
}

class HmacDigestTests {

    private val digester = HmacDigester(key)

    @Test
    fun `should digest message`() {
        val digested = digester.digest(MESSAGE.toBytes())

        assertThat(digested.toBase64String(), equalTo(HMAC_MESSAGE))
    }

    @Test
    fun `should digest message by parts`() {
        val digested = digester.digest(MESSAGE_PART_A.toBytes(), MESSAGE_PART_B.toBytes())

        assertThat(digested.toBase64String(), equalTo(HMAC_MESSAGE))
    }
}

class HashCreateTests {

    @Test
    fun `should create a SHA-256 hash digester`() {
        val digester = HashDigester()

        assertThat(digester.algorithm, equalTo(HashAlgorithms.SHA_256))
    }

    @Test
    fun `should create a SHA-1 hash digester`() {
        val digester = HashDigester(algorithm = HashAlgorithms.SHA_1)

        assertThat(digester.algorithm, equalTo(HashAlgorithms.SHA_1))
    }

    @Test
    fun `should create a MD5 hash digester`() {
        val digester = HashDigester(algorithm = HashAlgorithms.MD5)

        assertThat(digester.algorithm, equalTo(HashAlgorithms.MD5))
    }
}

class HashDigestTests {

    private val digester = HashDigester()

    @Test
    fun `should digest message`() {
        val digested = digester.digest(MESSAGE.toBytes())

        assertThat(digested.toBase64String(), equalTo(SHA256_MESSAGE))
    }

    @Test
    fun `should digest message in parts`() {
        val digested = digester.digest(MESSAGE_PART_A.toBytes(), MESSAGE_PART_B.toBytes())

        assertThat(digested.toBase64String(), equalTo(SHA256_MESSAGE))
    }
}