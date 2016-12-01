# krypto [![Travis](https://img.shields.io/travis/rs3vans/krypto.svg)](https://travis-ci.org/rs3vans/krypto) [![Bintray](https://img.shields.io/bintray/v/rs3vans/maven/krypto.svg)](https://bintray.com/rs3vans/maven/krypto) #
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

## Prerequisites ##
* `krypto` requires JDK 8 or higher.
* `krypto` is tested on Kotlin version 1.0.5-2
* Use of _strong_ keys for encryption may require the installation of the [JCE Unlimited Strength Jurisdiction Policy](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html) files.

## Use ##
For instructions on use and examples, please check out the `krypto` [wiki](https://github.com/rs3vans/krypto/wiki).

Additionally, please read the [API reference documentation](https://rs3vans.github.io/krypto).

## Download ##
`krypto` source can be downloaded from [GitHub](https://github.com/rs3vans/krypto).
`krypto` binaries can be downloaded from [Bintray](https://bintray.com/rs3vans/maven/krypto).

### Gradle ###
You can add `krypto` to your project using Gradle by adding the following to your `build.gradle` dependencies:

```groovy
compile 'com.github.rs3vans.krypto:krypto:1.1.0'
```
    
### Maven ###
You can add `krypto` to your project using Gradle by adding the following to your `build.gradle` dependencies:

```xml
<dependency>
  <groupId>com.github.rs3vans.krypto</groupId>
  <artifactId>krypto</artifactId>
  <version>1.1.0</version>
</dependency>
```

## License
`krypto` is licensed under the [MIT License](https://opensource.org/licenses/MIT).
