package org.rs3vans.kt.krypto

import org.junit.Assert.assertEquals
import org.junit.Test
import org.rs3vans.kt.krypto.key.PasswordBasedKey
import org.rs3vans.kt.krypto.key.RandomKey

class KeyTests {

    @Test
    fun testPasswordBasedKey() {
        val password = "my_password".toCharArray()
        val key = PasswordBasedKey(password, "HmacSHA1")

        assertEquals("HmacSHA1", key.derivationAlgorithm)
        assertEquals("AES", key.algorithm)
        assertEquals(16, key.bytes.size)
        assertEquals(8, key.salt.size)
    }

    @Test
    fun testRandomKey() {
        val key = RandomKey.generate()

        assertEquals(RandomKey.DEFAULT_ALGORITHM, key.algorithm)
        assertEquals(RandomKey.DEFAULT_SIZE / 8, key.bytes.size)
    }
}