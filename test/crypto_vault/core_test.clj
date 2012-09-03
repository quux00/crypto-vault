(ns crypto-vault.core-test
  (:use clojure.test
        crypto-vault.core)
  (:require [clojure.string :as str])
  (:import (java.io File)))

;; ---[ Test Data Setup ]--- ;;

(def passw "#jesIkj3a09IIgbl3.3")
(def keystore-fname "safe.keystore")
(def gettysburg-address
  "Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal.

Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting place for those who here gave their lives that that nation might live. It is altogether fitting and proper that we should do this.

But, in a larger sense, we can not dedicate -- we can not consecrate -- we can not hallow -- this ground. The brave men, living and dead, who struggled here, have consecrated it, far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us -- that from these honored dead we take increased devotion to that cause for which they gave the last full measure of devotion -- that we here highly resolve that these dead shall not have died in vain -- that this nation, under God, shall have a new birth of freedom -- and that government of the people, by the people, for the people, shall not perish from the earth.")

;; gettysburg address as list of sentences
(def gettysburg-addr-sentences
  (map #(str % ".") (str/split gettysburg-address #"\.")))

;; ---[ FIXTURE (setup/teardown ]--- ;;

(defn one-time-teardown []
  (doseq [fname [keystore-fname "tiger.boy" "gettys.addr" "seq.enc" "seq2.enc"]]
    (.delete (File. fname))))

(defn once-fixture [f]
  (f)
  (one-time-teardown))

(use-fixtures :once once-fixture)


;; ---[ TESTS ]--- ;;

(deftest test-create-keystore
  (let [f (File. keystore-fname)
        vault (->CryptoVault keystore-fname passw)
        key (get-secret-key-from-keystore vault)]
    (is (.exists f))
    (is (.isFile f))
    (is (not (nil? key)))
    ))

(deftest test-encrypt-decrypt
  (let [vault (->CryptoVault keystore-fname passw)
        key (get-secret-key-from-keystore vault)]

    (testing "Encrypt one simple string"
      (let [fname "tiger.boy"]
        (encrypt vault fname "Tiger Tiger Tiger")
        (let [msg (decrypt vault fname)]
          (is (not (nil? msg)))
          (is (= "Tiger Tiger Tiger" msg)))))
    
    (testing "Encrypt/decrypt large string"
      (let [fname "gettys.addr"]
        (encrypt vault fname gettysburg-address)
        (is (= gettysburg-address (decrypt vault fname)))))
    
    (testing "Encrypt a seq/list of strings"
      (let [fname "seq.enc"]
        (encrypt vault fname "Speech by Lincoln: " gettysburg-address)
        (is (= (str "Speech by Lincoln: " gettysburg-address)
               (decrypt vault fname)))        )
      (let [fname "seq2.enc"]
        (encrypt vault fname gettysburg-address)
        (is (= gettysburg-address (decrypt vault fname)))
        )
      )
    ))

