<?php

namespace MinVWS\Crypto\Laravel;

interface CmsCryptoInterface
{
    public function encrypt(string $plainText): string;
    public function decrypt(string $cipherText): string;
}
