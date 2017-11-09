package com.github.rs3vans.krypto

import org.hamcrest.CoreMatchers.equalTo
import org.hamcrest.MatcherAssert.assertThat
import org.junit.Test

private const val PASSWORD = "really secure password YO!"
private const val HASH = "v0jmlOb5PaAoJCV1Ci/5D9t/Wml5yOIx"

class PasswordTests {

    private val salt = byteArrayOf(-37, 127, 90, 105, 121, -56, -30, 49).toBytes()

    @Test
    fun `should hash the password`() {
        val hash = hashPassword(PASSWORD, salt)

        assertThat(hash, equalTo(HASH))
    }

    @Test
    fun `should match the password`() {
        val matches = matchesPasswordHash(PASSWORD, HASH)

        assertThat(matches, equalTo(true))
    }

    @Test
    fun `should NOT match the password`() {
        val matches = matchesPasswordHash(PASSWORD + "123", HASH)

        assertThat(matches, equalTo(false))
    }
}