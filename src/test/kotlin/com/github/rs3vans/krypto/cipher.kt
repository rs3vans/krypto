package com.github.rs3vans.krypto

import org.junit.Assert.assertEquals
import org.junit.Test
import com.github.rs3vans.krypto.key.Key
import com.github.rs3vans.krypto.util.decodBase64
import com.github.rs3vans.krypto.util.encodeBase64String

const val KEY = "itjy6ug21s7YAcUAC5a/+g=="
const val MESSAGE = "Hello World!"
const val ENCRYPTED_MESSAGE = "gUMO7Rn0qYOVYWeO42QX+w=="
const val IV = "Akli2l0AR1DwOVGQ4+b4tw=="

class CipherTests {

    val key = Key(KEY.decodBase64())
    val cipher = Cipher(key)

    @Test
    fun testEncrypt() {
        val (bytes, iv) = cipher.encrypt(MESSAGE.toByteArray(), IV.decodBase64())

        assertEquals(bytes.encodeBase64String(), ENCRYPTED_MESSAGE)
        assertEquals(iv.encodeBase64String(), IV)
    }

    @Test
    fun testDecrypt() {
        val decrypted = cipher.decrypt(Encrypted(ENCRYPTED_MESSAGE.decodBase64(), IV.decodBase64()))

        assertEquals(MESSAGE, decrypted.toString(Charsets.UTF_8))
    }
}