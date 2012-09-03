(ns crypto-vault.core
  (:require [clojure.java.io :as jio])
  (:import (javax.crypto Cipher KeyGenerator
                         CipherOutputStream CipherInputStream)
           (java.io File FileInputStream FileOutputStream)
           (java.security Key KeyStore KeyStore$SecretKeyEntry
                          KeyStore$PasswordProtection)))

;; ---[ Data Structures Defs ]--- ;;

;; CryptoVault holds the name that the JCE KeyStore is stored in
;; and the password to encrypt/decrypt that keystore
;; the vault can then encrypt/decrypt any number of files - you
;; pass the text to encrypt and file name to encrypt it to in the
;; encypt function and use the decrypt function to reverse it
;; back into plaintext (in memory - the file on disk stays encrypted)
(defrecord CryptoVault [keystore-fname passwd])

;; ---[ Functions ]--- ;;

(defn- init-keystore
  "If no keystore has yet been created on disk, call this method with
   a newly created java.security.KeyStore and a CryptoVault record"
  {:private true}
  [keystore vault]
  (let [passw  (.toCharArray (.passwd vault))
        key    (.generateKey (KeyGenerator/getInstance "AES"))]
    ;; load nil means create an empty keystore (in memory)
    (.load keystore nil passw)
    (.setEntry keystore "vault-key"
               (KeyStore$SecretKeyEntry. key)
               (KeyStore$PasswordProtection. passw))
    (.store keystore (FileOutputStream. (:keystore-fname vault)) passw)
    key))

(defn- load-keystore 
  "If a keystore has been created on disk, call this method with
   a java.security.KeyStore and a CryptoVault record"
  {:private true}
  [keystore vault]
  (let [passw (.toCharArray (.passwd vault))]
    (.load keystore (FileInputStream. (:keystore-fname vault)) passw)
    (.getKey keystore "vault-key", passw)))


(defn get-secret-key-from-keystore 
  "Before calling encrypt or decrypt with a CryptoVault record, first
   call this function either create a new KeyStore or load it from
   file if it has already been created. Encryption/decryption of other
   files cannot occur until a KeyStore exists."
  [^CryptoVault vault]
  (let [ks-file  (File. (:keystore-fname vault))
        keystore (KeyStore/getInstance "JCEKS")]
    (if (.exists ks-file)
      (try
        (load-keystore keystore vault)
        (catch Exception e (init-keystore keystore vault)))
      (init-keystore keystore vault))))


(defn- init-cipher
  "Create and initialize a javax.crypto.Cipher object. Pass a a CryptoVault record
   (in order to get its keystore) and either :encrypt or :decrypt keyword to
   specify the mode of the cipher"
  [^CryptoVault vault enc-dec]  
  {:private true}
  (let [mode (if (= :encrypt enc-dec) Cipher/ENCRYPT_MODE Cipher/DECRYPT_MODE)]
    (doto (Cipher/getInstance "AES")
      (.init mode (get-secret-key-from-keystore vault)))))


(defn encrypt
  "Encrypt arbitrary text to a file using the CryptoVault's KeyStore.
   The CryptoVault must alreay have a KeyStore loaded, so call 
   get-secret-key-from-keystore first.  Pass in the filename (not a File
   object) to encrypt the text to and then the text to encrypt.  The
   text to encrypt can be:
    - a single string
    - a series of strings (varargs style)
    - a collection of strings
    - any combination of the above.
   Note that this method will overwrite, not append to, any data already
   in the +fname+ file."
  [^CryptoVault vault ^String fname msg & msgs]
  (let [cipher (init-cipher vault :encrypt)
        outstm (FileOutputStream. fname)
        msgseq (flatten (conj msgs msg))]
    (with-open [cos (CipherOutputStream. outstm cipher)]
      (doseq [entry msgseq]
        (.write cos (.getBytes entry))))))  

(defn decrypt
  "Decrypt text from a file that was encrypted using the CryptoVault's KeyStore.
   The CryptoVault must alreay have a KeyStore loaded, so call 
   get-secret-key-from-keystore first.  Pass in the filename (not a File
   object) to decrypt the text from."
  [^CryptoVault vault ^String fname]
  (let [cipher (init-cipher vault :decrypt)
        instm (FileInputStream. fname)
        buf (make-array Byte/TYPE 256)
        sb (StringBuilder.)]

    ;; TODO: can we use reader here?
    (with-open [cis (CipherInputStream. instm cipher)]
      (loop [n (.read cis buf)]
        (when-not (neg? n)
          (.append sb (String. buf 0 n))
          (recur (.read cis buf)))))
    (str sb)))
