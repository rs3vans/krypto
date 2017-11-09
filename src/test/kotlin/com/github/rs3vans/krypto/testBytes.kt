package com.github.rs3vans.krypto

import org.hamcrest.CoreMatchers.equalTo
import org.hamcrest.MatcherAssert.assertThat
import org.junit.Test
import java.io.Serializable

private const val STRING = "foo"
private const val BYTES_BASE64 = "Zm9v"
private const val BYTES_HEX = "666F6F"

class BytesTests {

    private val bytes = STRING.toBytes()

    @Test
    fun `it should convert to Base64`() {
        val base64 = bytes.toBase64String()

        assertThat(base64, equalTo(BYTES_BASE64))
    }

    @Test
    fun `it should convert from Base64`() {
        val b = BYTES_BASE64.toBytesFromBase64()

        assertThat(b, equalTo(bytes))
    }

    @Test
    fun `it should convert to Hex`() {
        val hex = bytes.toHexString()

        assertThat(hex, equalTo(BYTES_HEX))
    }

    @Test
    fun `it should convert from Hex`() {
        val b = BYTES_HEX.toBytesFromHex()

        assertThat(b, equalTo(bytes))
    }

    @Test
    fun `it should decode back to a string`() {
        val string = bytes.toDecodedString()

        assertThat(string, equalTo(STRING))
    }

    @Test
    fun `it should serialize an object to and from bytes`() {
        val thing = Thing(STRING)
        val thingBytes = thing.serializeToBytes()
        val deserializedThing = thingBytes.deserializeToObject<Thing>()

        assertThat(deserializedThing, equalTo(thing))
    }

    private data class Thing(val string: String) : Serializable
}
