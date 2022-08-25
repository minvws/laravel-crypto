<?php

namespace MinVWS\Crypto\Laravel\Service\Signature;

use MinVWS\Crypto\Laravel\CryptoException;
use MinVWS\Crypto\Laravel\SignatureCryptoInterface;
use MinVWS\Crypto\Laravel\SignatureSignCryptoInterface;
use MinVWS\Crypto\Laravel\SignatureVerifyCryptoInterface;

class NativeService implements SignatureCryptoInterface, SignatureSignCryptoInterface, SignatureVerifyCryptoInterface
{
    /** @var ?string */
    protected $certPath;
    /** @var ?string */
    protected $privKeyPath;
    /** @var ?string */
    protected $privKeyPass;
    /** @var ?string */
    protected $certChainPath;

    /**
     * NativeService constructor.
     *
     * @param string|null $certPath
     * @param string|null $privKeyPath
     * @param string|null $privKeyPass
     * @param string|null $certChainPath
     */
    public function __construct(?string $certPath = null, ?string $privKeyPath = null, ?string $privKeyPass = null, ?string $certChainPath = null)
    {
        $this->certPath = $certPath;
        $this->privKeyPath = $privKeyPath;
        $this->privKeyPass = $privKeyPass;
        $this->certChainPath = $certChainPath;
    }

    /**
     * @param string $payload
     * @param bool $detached
     * @return string
     */
    public function sign(string $payload, bool $detached = false): string
    {
        if (!is_readable($this->privKeyPath)) {
            throw CryptoException::cannotReadFile($this->privKeyPath);
        }

        $tmpFileSignature = null;
        $tmpFileData = null;

        try {
            $tmpFileData = tmpfile();
            if (!is_resource($tmpFileData)) {
                throw CryptoException::sign("cannot create temp file on disk");
            }
            $tmpFileDataPath = stream_get_meta_data($tmpFileData)['uri'];
            file_put_contents($tmpFileDataPath, $payload);

            $tmpFileSignature = tmpfile();
            if (!is_resource($tmpFileSignature)) {
                throw CryptoException::sign("cannot create temp file on disk");
            }
            $tmpFileSignaturePath = stream_get_meta_data($tmpFileSignature)['uri'];

            $headers = array();

            $flags = 0;
            if ($detached) {
                $flags |= OPENSSL_CMS_DETACHED;
            }

            // Sign it
            openssl_cms_sign(
                $tmpFileDataPath,
                $tmpFileSignaturePath,
                $this->certPath,
                array($this->privKeyPath, $this->privKeyPass),
                $headers,
                $flags,
                OPENSSL_ENCODING_DER,
                $this->certChainPath
            );

            // Grab signature contents
            $signature = file_get_contents($tmpFileSignaturePath);
            if ($signature === false) {
                throw CryptoException::sign("could not read signature from disk");
            }

            return base64_encode($signature);
        } finally {
            // Close/remove temp files, even when errored
            if (is_resource($tmpFileData)) {
                fclose($tmpFileData);
            }
            if (is_resource($tmpFileSignature)) {
                fclose($tmpFileSignature);
            }
        }
    }

    /**
     * @param string $signedPayload
     * @param string|null $content
     * @param string|null $certificate
     * @return bool
     */
    public function verify(string $signedPayload, string $content = null, string $certificate = null): bool
    {
        $tmpFileContentData = null;
        $tmpFileContentDataPath = null;
        $tmpFileSignedData = null;
        $tmpFileSignedDataPath = null;
        $tmpFileCertificateData = null;
        $tmpFileCertificateDataPath = null;

        try {
            $detached = !is_null($content);

            /** @var resource $tmpFileSignedData */
            $tmpFileSignedData = tmpfile();
            if (!is_resource($tmpFileSignedData)) {
                throw CryptoException::verify("cannot create temp file on disk");
            }
            $tmpFileSignedDataPath = stream_get_meta_data($tmpFileSignedData)['uri'];
            file_put_contents($tmpFileSignedDataPath, base64_decode($signedPayload));

            $flags = OPENSSL_CMS_NOVERIFY;
            if ($detached) {
                $flags |= OPENSSL_CMS_DETACHED;

                /** @var resource $tmpFileContentData */
                $tmpFileContentData = tmpfile();
                if (!is_resource($tmpFileContentData)) {
                    throw CryptoException::verify("cannot create temp file on disk");
                }
                $tmpFileContentDataPath = stream_get_meta_data($tmpFileContentData)['uri'];
                file_put_contents($tmpFileContentDataPath, $content);
            }

            if ($certificate) {
                $flags |= OPENSSL_CMS_NOINTERN;

                /** @var resource $tmpFileCertificateData */
                $tmpFileCertificateData = tmpfile();
                if (!is_resource($tmpFileCertificateData)) {
                    throw CryptoException::verify("cannot create temp file on disk");
                }
                $tmpFileCertificateDataPath = stream_get_meta_data($tmpFileCertificateData)['uri'];
                file_put_contents($tmpFileCertificateDataPath, $certificate);
            }

            /*
               NOTE: Detached verification is special, it means the content and signature arguments
               must be switched around.
            */

            // Verify it
            $res = openssl_cms_verify(
                ($detached ? $tmpFileContentDataPath : $tmpFileSignedDataPath) ?? '',
                $flags,
                null,
                array(),
                $tmpFileCertificateDataPath,
                null,
                null,
                $detached ? $tmpFileSignedDataPath : $tmpFileContentDataPath,
                OPENSSL_ENCODING_DER,
            );

            return $res;
        } finally {
            // Close/remove temp files, even when errored
            if (is_resource($tmpFileSignedData)) {
                fclose($tmpFileSignedData);
            }
            if (is_resource($tmpFileContentData)) {
                fclose($tmpFileContentData);
            }
            if (is_resource($tmpFileCertificateData)) {
                fclose($tmpFileCertificateData);
            }
        }
    }
}
