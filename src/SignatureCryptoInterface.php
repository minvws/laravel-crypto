<?php

namespace MinVWS\Crypto\Laravel;

use MinVWS\Crypto\Laravel\Service\Signature\SignatureVerifyConfig;

interface SignatureCryptoInterface
{
    /**
     * @param string $payload The actual payload to sign.
     * @param bool $detached If false, the payload will be added to the signed message and you do not need to specify
     *                        the content when verifying the message.
     * @return string Signed CMS block data (in DER format)
     */
    public function sign(string $payload, bool $detached = false): string;

    /**
     * @param string $signedPayload The signed CMS block data (in DER format)
     * @param string|null $content Optional content to verify against. ONLY needed when you created a detached signature
     * @param string|null $certificate Optional certificate to verify against.
     * @param SignatureVerifyConfig|null $verifyConfig Optional verify config.
     * @return bool True when the verification is successful. False otherwise.
     */
    public function verify(
        string $signedPayload,
        string $content = null,
        string $certificate = null,
        ?SignatureVerifyConfig $verifyConfig = null
    ): bool;
}
