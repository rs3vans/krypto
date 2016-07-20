package org.rs3vans.kt.krypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordTests {

    @Test
    fun testHashPassword() {
        val hash = PASSWORD.hashPassword(salt)

        assertEquals(HASH, hash)
    }

    @Test
    fun testMatchesPasswordHash() {
        assertTrue(PASSWORD.matchesPasswordHash(HASH))
    }

    companion object {

        const val PASSWORD = "really secure password YO!"
        const val HASH = "v0jmlOb5PaAoJCV1Ci/5D9t/Wml5yOIx"

        val salt = byteArrayOf(-37, 127, 90, 105, 121, -56, -30, 49)
    }
}