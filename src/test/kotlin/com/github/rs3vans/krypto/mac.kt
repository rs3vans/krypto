package com.github.rs3vans.krypto

import com.github.rs3vans.krypto.key.Key
import com.github.rs3vans.krypto.message.Mac
import com.github.rs3vans.krypto.util.decodeBase64
import com.github.rs3vans.krypto.util.encodeBase64String
import org.junit.Assert.assertEquals
import org.junit.Test

class MacTests {

    val key = Key(CipherTests.KEY.decodeBase64())
    val mac = Mac(key)

    @Test
    fun testCreate() {
        val hmac = mac.create(MESSAGE.toByteArray()).encodeBase64String()

        assertEquals(HMAC, hmac)
    }

    companion object {

        const val KEY = "itjy6ug21s7YAcUAC5a/+g=="
        const val MESSAGE = "Hello World!"
        const val HMAC = "3aZ8watUQFJj5ViEJQlt7RUi4C8+ItnHkduwbt3W558="
    }
}