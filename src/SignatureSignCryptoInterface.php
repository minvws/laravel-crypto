<?php

namespace MinVWS\Crypto\Laravel;

interface SignatureSignCryptoInterface
{
    /**
     * @param string $payload The actual payload to sign.
     * @param bool $detached If false, the payload will be added to the signed message and you do not need to specify
     *                        the content when verifying the message.
     * @return string Signed CMS block data (in DER format)
     */
    public function sign(string $payload, bool $detached = false): string;
}
