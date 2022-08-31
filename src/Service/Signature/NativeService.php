<?php

namespace MinVWS\Crypto\Laravel\Service\Signature;

use MinVWS\Crypto\Laravel\Exceptions\CryptoException;
use MinVWS\Crypto\Laravel\SignatureCryptoInterface;
use MinVWS\Crypto\Laravel\Traits\TempFiles;

class NativeService implements SignatureCryptoInterface
{
    use TempFiles;

    protected string $certPath;
    protected string $privKeyPath;
    protected string $privKeyPass;
    protected string $certChainPath;

    /**
     * NativeService constructor.
     *
     * @param string|null $certPath
     * @param string|null $privKeyPath
     * @param string|null $privKeyPass
     * @param string|null $certChainPath
     */
    public function __construct(
        ?string $certPath = null,
        ?string $privKeyPath = null,
        ?string $privKeyPass = null,
        ?string $certChainPath = null
    ) {
        $this->certPath = $certPath ?? '';
        $this->privKeyPath = $privKeyPath ?? '';
        $this->privKeyPass = $privKeyPass ?? '';
        $this->certChainPath = $certChainPath ?? '';
    }

    /**
     * @param string $payload
     * @param bool $detached
     * @return string
     */
    public function sign(string $payload, bool $detached = false): string
    {
        if (!is_readable($this->certPath)) {
            throw CryptoException::cannotReadFile($this->certPath);
        }
        if (!is_readable($this->privKeyPath)) {
            throw CryptoException::cannotReadFile($this->privKeyPath);
        }
        if (!empty($this->certChainPath) && !is_readable($this->certChainPath)) {
            throw CryptoException::cannotReadFile($this->certChainPath);
        }

        $tmpFileSignature = null;
        $tmpFileData = null;

        try {
            $tmpFileData = $this->createTempFileWithContent($payload);

            $tmpFileSignature = $this->createTempFile();
            $tmpFileSignaturePath = $this->getTempFilePath($tmpFileSignature);

            $headers = array();

            $flags = 0;
            if ($detached) {
                $flags |= OPENSSL_CMS_DETACHED;
            }

            // Sign it
            openssl_cms_sign(
                input_filename: $this->getTempFilePath($tmpFileData),
                output_filename: $tmpFileSignaturePath,
                certificate: "file://" . $this->certPath,
                private_key: array("file://" . $this->privKeyPath, $this->privKeyPass),
                headers: $headers,
                flags: $flags,
                encoding: OPENSSL_ENCODING_DER,
                untrusted_certificates_filename: $this->certChainPath
            );

            // Grab signature contents
            $signature = file_get_contents($tmpFileSignaturePath);
            if ($signature === false) {
                throw CryptoException::sign("could not read signature from disk");
            }

            return base64_encode($signature);
        } finally {
            // Close/remove temp files, even when errored
            $this->closeTempFile($tmpFileData);
            $this->closeTempFile($tmpFileSignature);
        }
    }

    /**
     * @param string $signedPayload
     * @param string|null $content
     * @param string|null $certificate
     * @param SignatureVerifyConfig|null $verifyConfig
     * @return bool
     */
    public function verify(
        string $signedPayload,
        string $content = null,
        string $certificate = null,
        ?SignatureVerifyConfig $verifyConfig = null
    ): bool {
        $verifyConfig = $verifyConfig ?? new SignatureVerifyConfig();

        $tmpFileContentData = null;
        $tmpFileContentDataPath = null;
        $tmpFileSignedData = null;
        $tmpFileCertificateData = null;
        $tmpFileCertificateDataPath = null;

        try {
            $detached = !is_null($content);

            $tmpFileSignedData = $this->createTempFileWithContent(base64_decode($signedPayload));
            $tmpFileSignedDataPath = $this->getTempFilePath($tmpFileSignedData);

            $flags = $this->getOpenSslTags($verifyConfig);
            if ($detached) {
                $flags |= OPENSSL_CMS_DETACHED;

                $tmpFileContentData = $this->createTempFileWithContent($content);
                $tmpFileContentDataPath = $this->getTempFilePath($tmpFileContentData);
            }

            if ($certificate) {
                $flags |= OPENSSL_CMS_NOINTERN;

                $tmpFileCertificateData = $this->createTempFileWithContent($certificate);
                $tmpFileCertificateDataPath = $this->getTempFilePath($tmpFileCertificateData);
            }

            /*
               NOTE: Detached verification is special, it means the content and signature arguments
               must be switched around.
            */

            // Verify it
            $res = openssl_cms_verify(
                input_filename: ($detached ? $tmpFileContentDataPath : $tmpFileSignedDataPath) ?? '',
                flags: $flags,
                certificates: null,
                ca_info: array($this->certChainPath),
                untrusted_certificates_filename: $tmpFileCertificateDataPath,
                content: null,
                pk7: null,
                sigfile: $detached ? $tmpFileSignedDataPath : $tmpFileContentDataPath,
                encoding: OPENSSL_ENCODING_DER,
            );

            return $res;
        } finally {
            // Close/remove temp files, even when errored
            $this->closeTempFile($tmpFileSignedData);
            $this->closeTempFile($tmpFileContentData);
            $this->closeTempFile($tmpFileCertificateData);
        }
    }

    protected function getOpenSslTags(SignatureVerifyConfig $config): int
    {
        $flags = 0;
        if ($config->getBinary()) {
            $flags |= OPENSSL_CMS_BINARY;
        }
        if ($config->getNoVerify()) {
            $flags |= OPENSSL_CMS_NOVERIFY;
        }

        return $flags;
    }
}
