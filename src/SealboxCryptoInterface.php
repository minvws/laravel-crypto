<?php

namespace MinVWS\Crypto\Laravel;

interface SealboxCryptoInterface
{
    public function encrypt(string $plainText): string;
    public function decrypt(string $cipherText): string;
}
