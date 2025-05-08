<?php

namespace MinVWS\Crypto\Laravel\Service\Sealbox;

use Exception;
use MinVWS\Crypto\Laravel\Exceptions\CryptoException;
use MinVWS\Crypto\Laravel\SealboxCryptoInterface;

class SealboxService implements SealboxCryptoInterface
{
    protected ?string $recipientPubKey;     // Public key to encrypt with
    protected ?string $privKey;             // Private key to decrypt with

    public function __construct(?string $privKey, ?string $recipientPubKey)
    {
        $this->privKey = $privKey ? base64_decode($privKey) : null;
        $this->recipientPubKey = $recipientPubKey ? base64_decode($recipientPubKey) : null;
    }

    public function encrypt(string $plainText): string
    {
        if (! $this->recipientPubKey) {
            throw CryptoException::encrypt("no recipient public key provided");
        }

        try {
            $ciphertext = sodium_crypto_box_seal($plainText, $this->recipientPubKey);
        } catch (Exception $e) {
            throw CryptoException::encrypt($e->getMessage());
        }

        return $ciphertext;
    }

    public function decrypt(string $cipherText): string
    {
        if (! $this->recipientPubKey) {
            throw CryptoException::encrypt("no recipient public key provided");
        }
        if (! $this->privKey) {
            throw CryptoException::encrypt("no private key provided");
        }

        try {
            $keyPair = sodium_crypto_box_keypair_from_secretkey_and_publickey(
                $this->privKey ?? "",
                $this->recipientPubKey ?? ""
            );

            $plaintext = sodium_crypto_box_seal_open($cipherText, $keyPair);
            if ($plaintext === false) {
                throw CryptoException::decrypt("sealbox could not be opened");
            }
        } catch (Exception $e) {
            throw CryptoException::decrypt($e->getMessage());
        }

        return $plaintext;
    }
}
