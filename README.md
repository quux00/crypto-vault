# crypto-vault

A Clojure library designed to encrypt and decrypt text to and from files using the javax.crypto.Cipher and java.security.KeyStore and related classes. By default, it uses the AES cipher.

This library is based on the CryptoVault example in the 2nd ed. of [Programming Clojure](http://pragprog.com/book/shcloj2/programming-clojure).  The Java code is basic a direct port of the Clojure code in the book.

The Clojure code here, however, is (what I consider to be) a bit of a simplification of the API.  I also provide a clojure.test unit test for it.

## Usage

To use you need to do three things:

1. Create a CryptoVault record defining the name of the keystore file and a password to lock/unlock that keystore.
2. Create or load the SecretKey from the keystore file
3. Use the SecretKey to either encrypt or decrypt text to/from a file

    (def vault (->CryptoVault "my.keystore" "secret-password-123"))

    (def key (get-secret-key-from-keystore vault))

    (encrypt vault "myfile.enc" "Text to encrypt." "More text to encrypt.")

    (def plaintext (decrypt vault "myfile.enc"))

See the unit test for a working example.

## License

Copyright © 2012 Michael Peterson

Distributed under the Eclipse Public License, the same as Clojure.
