# Crypto 101 (as used by brba et al)

## CMS

CMS stands for Cryptographic Signed Message[2] and provides a format for signed and/or encrypted data. It is almost 
identical to other formats like PKCS#7 and S/MIME and in this document, all three should be considered equal.

Since CMS is an envelope format, there can be all kind of different crypto inside. Our system will exclusively use the
AES256-CBC encryption method. CMS consists of an ASN.1 structure (like you can define a structure with JSON, or XML) 
and defines whats inside the envelope. The envelope can be encoded with different kind of encodings like PEM or DER. We
encode our envelopes in the DER format, which is a binary format so it should preferably be encoded with base64 for 
easier transmission over networks.

> Note that base64 encoding will INCREASE the data size with +- 33%. A bin2hex encoding will increase your data 
> size with 50%. If a separate encoding is needed, prefer base64 over hex.

A CMS envelope consists of the following data:
    - a set of 1 or more certificates that can be used to decrypt the data. Each set consists of the subject of the 
      certificate and a key that is encrypted with the PUBLIC KEY of that certificate. 
    - a encryption method.
    - an IV (initialization vector)
    - the encrypted data.

                    +---------------------+
                    | Cert 1              |
                    |   +-----------------+
                    |   | Subject         |
                    |   +-----------------+
                    |   | Encrypted Key   |
                    |   +-----------------+
                    +---------------------+
                    | Cert 2              |
                    |   +-----------------+
                    |   | Subject         |
                    |   +-----------------+
                    |   | Encrypted Key   |
                    |   +-----------------+
                    +---------------------+
                    | Cert N              |
                    |   +-----------------+
                    |   | Subject         |
                    |   +-----------------+
                    |   | Encrypted Key   |
                    |   +-----------------+
                    +---------------------+
                    | Encryption method   |
                    +---------------------+
                    | IV                  |
                    +---------------------+
                    | Encrypted payload   |
                    +---------------------+


CMS creates an encrypted envelop the following way:
  - First, it will generate an IV and key for encrypting the actual data with AES256 (provided this is the encryption 
    method we use).
  - Then, it will encrypt the data with this IV and key. Note that this is a symmetrical key, so the exact same key can
    be used to decrypt the data.
  - For each certificate that is given, it will add the cert information (Subject) to the envelope. Then it will 
    encrypt the symmetrical key with the PUBLIC KEY found in the certificate.

This means a few things:
  - the main encryption of the payload data is done with a symmetrical key. This is because this is much faster than 
    encrypting it with a asymmetrical (RSA) key.
  - the only thing that is encrypted asymmetrical is the symmetrical key.
  - each certificate will encrypt the same symmetrical key.
  - The IV is send unencrypted in the data. This is because this is not secret data.



## Sealbox

A box allows you to encrypt data with a recipient's public key, where only the recipient's private key can decrypt 
the data. There are two different type of boxes: regular boxes, and sealboxes.

### Keys
First, keypairs are needed. Note that the key generated here should be elliptic curve keys[1]. The sodium key generator 
used will generate X25519[3] keys:

```php
    $keypair = sodium_crypto_box_keypair(); 
    print "Secret: " . base64_encode(sodium_crypto_box_secretkey($keypair)); 
    print "Public: " . base64_encode(sodium_crypto_box_publickey($keypair));
```    

> In brba, all keys are encoded in Base64 encoding (note: this is not always true, but should be) 

Even though these keys are much shorted in length than for instance RSA keys (often: 256bit vs 2048/4096bit), they 
are considered as strong or even stronger (256bit EC-key is roughly equivalent to a 3000bit RSA key). Computations with
EC keys are also much easier and less CPU intense.

### sodium_box
For using the `sodium_box` method, you need to exchange the sender and recipient's PUBLIC key. This is because both 
keys are used for generating a shared secret through a diffie-hellman key exchange. This method will calculate a secret 
that is always the same between two keypairs (thus Alice and Bob will always generate the same shared DH secret).

Besides Alice secret key, and Bob's public key, there is also a need for a nonce. This could be random generated bytes  
or even a sequential number, as long as it is only used once. Bob needs to know this nonce in order to decrypt the data.

A benefit of this function is that you can verify the authenticity of the sender, as the generated secret could only 
be generated by the private-key holder of the sender's public key.

### (Anonymous) SealBoxes

Sealboxes[4] work a little bit different. Instead of Alice needing to know Bob's public key and vice versa, Alice only 
need to know Bob's public key. Bob does NOT need to know Alice public key, meaning there is less information to be 
exchanged (like setting the keys in a configuration file). For this function, you also do not need to generate and send
over a nonce.

To encrypt a message, Alice uses the `crypto_box_seal` method with Bob's public key. The function will then generate an 
ephemeral key (this key, unlike Alice's key, is only used for one single encryption). At this point, it will generate a 
regular box with the ephemeral secret key and Bob's public key, plus a calculated nonce generated (with the blake2b 
method) with the ephemeral public key and Bob's public key as input.

The sealbox consists of the the emphemeral public key part, and the (regular) box. The emphemeral secret part is 
destroyed so only Bob can decode the message (not even Alice).

Decryption works this way:
Bob can decrypt the message by using the `crypto_box_seal_open` method with Bob's secret key and public key. Bob gets 
the ephemeral key and the box. It will do a Diffie-Hellman key exchange between Bob's secret key and the 
ephemeral public key. This results in a shared secret that can be used to decrypt the box. The nonce for the box can be 
found by calculating the nonce with the blake2b method with the ephemeral public key (as found in the sealbox), and 
Bob's public key. This results in the same nonce that will be used for decrypting the message.

Because we use an ephemeral key in sealboxes, we never know anything about Alice. Therefor we cannot authenticate 
that the message originated from Alice.

### Diffie-Hellman:

Diffie-Hellman[5] allows you to easily generate shared secrets with just knowing the public part of another (EC) keypair.
 
    Ephemeral Secret key (ES)
    Ephemeral Public key (EP)
    Bob secret Key (BP)    
    Bob public Key (BP)

    DiffieHellman(ES, BP) -> shared secret
    DiffieHellman(EP, BS) -> same shared secret



## CMS signatures 
CMS can also be used for signing data [6]. It works a bit like the encryption method, except we don't encrypt the payload,
but we encrypt the HASH of the payload. We encrypt the symmetrical encryption key with each of the certificates 
PRIVATE keys. Often, only one certificate is used.

Brba uses the sha256 as the hashing function and we do not attach the actual data to the CMS. This means you can only
verify the CMS data with the following information:

  - the actual data that is used for signing
  - the cms signature data
  - the public key for any of the certificates that is used for signing the CMS signature.


---
- [1] https://www.globalsign.com/en/blog/elliptic-curve-cryptography
- [2] https://en.wikipedia.org/wiki/Cryptographic_Message_Syntax
- [3] https://en.wikipedia.org/wiki/Curve25519
- [4] https://doc.libsodium.org/public-key_cryptography/sealed_boxes
- [5] https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
- [6] https://www.openssl.org/docs/man1.0.2/man1/cms.html
- [7] https://lemire.me/blog/2019/01/30/what-is-the-space-overhead-of-base64-encoding/