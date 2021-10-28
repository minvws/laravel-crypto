<?php

namespace MinVWS\Crypto\Laravel\Service\Sealbox;

use MinVWS\Crypto\Laravel\CryptoException;
use MinVWS\Crypto\Laravel\SealboxCryptoInterface;

class SealboxService implements SealboxCryptoInterface
{
    /** @var string */
    protected $recipientPubKey;

    /** @var string */
    protected $privKey;

    /**
     * SealboxService constructor.
     *
     * @param string $privKey
     * @param string $recipientPubKey
     * @throws \SodiumException
     */
    public function __construct(string $privKey, string $recipientPubKey)
    {
        $this->privKey = base64_decode($privKey);
        $this->recipientPubKey = base64_decode($recipientPubKey);
    }

    /**
     * @param string $plainText
     * @return string
     */
    public function encrypt(string $plainText): string
    {
        try {
            $ciphertext = sodium_crypto_box_seal($plainText, $this->recipientPubKey);
            if ($ciphertext == false) {
                throw CryptoException::encrypt();
            }
        } catch (\Exception $e) {
            throw CryptoException::encrypt($e->getMessage());
        }

        return $ciphertext;
    }

    /**
     * @param string $cipherText
     * @return string
     */
    public function decrypt(string $cipherText): string
    {
        try {
            $keyPair = sodium_crypto_box_keypair_from_secretkey_and_publickey(
                $this->privKey,
                $this->recipientPubKey
            );

            $plaintext = sodium_crypto_box_seal_open($cipherText, $keyPair);
            if ($plaintext == false) {
                throw CryptoException::decrypt("sealbox could not be opened");
            }
        } catch (\Exception $e) {
            throw CryptoException::decrypt($e->getMessage());
        }

        return $plaintext;
    }
}
