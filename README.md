# krypto
A [Kotlin](https://kotlinlang.org/) library for strong, two-way encryption.

## Overview
`krypto` makes strong, two-way encryption easier to deal with when developing in Kotlin.

`krypto` is more or less a wrapper around the
[Java Cryptography Architecture](http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html)
(JCA) API, making it easier to use from Kotlin applications.
This library was _not necessarily_ designed with maximum flexibility in mind,
but instead it enforces the use of _strong_ techniques for encryption.

## Motivation ##
In modern computing, encryption is a must when dealing with storage or transmission of sensitive data.
Performing encryption "the right way" on the JVM platform can be cumbersome and verbose.
`krypto` aims to make this task a bit easier, while not compromising on security.

## Disclaimer ##
Cryptography is a complex and often difficult-to-understand subject.
The author(s) of `krypto` make no claim of expert knowledge in cryptography --
by using this library you agree that you take on the responsibility of understanding the techniques that
it enables.
_The author(s) of `krypto` are not responsible for any loss or leakage of data, sensitive or otherwise._

## Use ##
For instructions on use and examples, please check out the `krypto` [wiki](https://github.com/rs3vans/krypto/wiki).

## Download ##
`krypto` source can be downloaded from [GitHub](https://github.com/rs3vans/krypto).

## License
`krypto` is licensed under the Apache Software License v2.0.
