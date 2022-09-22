<?php

namespace MinVWS\Crypto\Laravel\Service\Signature;

use MinVWS\Crypto\Laravel\Exceptions\CryptoException;
use MinVWS\Crypto\Laravel\SignatureCryptoInterface;
use MinVWS\Crypto\Laravel\TempFileInterface;

class NativeService implements SignatureCryptoInterface
{
    protected string $certPath;
    protected string $privKeyPath;
    protected string $privKeyPass;
    protected ?string $certChainPath;
    protected TempFileInterface $tempFileService;

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
        ?string $certChainPath = null,
        ?TempFileInterface $tempFileService = null,
    ) {
        $this->certPath = $certPath ?? '';
        $this->privKeyPath = $privKeyPath ?? '';
        $this->privKeyPass = $privKeyPass ?? '';
        $this->certChainPath = !empty($certChainPath) ? $certChainPath : null;
        $this->tempFileService = $tempFileService ?? app(TempFileInterface::class);
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
            $tmpFileData = $this->tempFileService->createTempFileWithContent($payload);

            $tmpFileSignature = $this->tempFileService->createTempFile();
            $tmpFileSignaturePath = $this->tempFileService->getTempFilePath($tmpFileSignature);

            $headers = array();

            $flags = 0;
            if ($detached) {
                $flags |= OPENSSL_CMS_DETACHED;
            }

            // Sign it
            openssl_cms_sign(
                input_filename: $this->tempFileService->getTempFilePath($tmpFileData),
                output_filename: $tmpFileSignaturePath,
                certificate: "file://" . $this->certPath,
                private_key: array("file://" . $this->privKeyPath, $this->privKeyPass),
                headers: $headers,
                flags: $flags,
                encoding: OPENSSL_ENCODING_DER,
                untrusted_certificates_filename: $this->certChainPath // TODO: Check this in signature ...
            );

            // Grab signature contents
            $signature = file_get_contents($tmpFileSignaturePath);
            if ($signature === false) {
                throw CryptoException::sign("could not read signature from disk");
            }

            return base64_encode($signature);
        } finally {
            // Close/remove temp files, even when errored
            $this->tempFileService->closeTempFile($tmpFileData);
            $this->tempFileService->closeTempFile($tmpFileSignature);
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

            $tmpFileSignedData = $this->tempFileService->createTempFileWithContent(base64_decode($signedPayload));
            $tmpFileSignedDataPath = $this->tempFileService->getTempFilePath($tmpFileSignedData);

            $flags = $this->getOpenSslTags($verifyConfig);
            if ($detached) {
                $flags |= OPENSSL_CMS_DETACHED;

                $tmpFileContentData = $this->tempFileService->createTempFileWithContent($content);
                $tmpFileContentDataPath = $this->tempFileService->getTempFilePath($tmpFileContentData);
            }

            if ($certificate) {
                $flags |= OPENSSL_CMS_NOINTERN;

                $tmpFileCertificateData = $this->tempFileService->createTempFileWithContent($certificate);
                $tmpFileCertificateDataPath = $this->tempFileService->getTempFilePath($tmpFileCertificateData);
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
                ca_info: !empty($this->certChainPath) ? array($this->certChainPath) : [],
                untrusted_certificates_filename: $tmpFileCertificateDataPath,
                content: null,
                pk7: null,
                sigfile: $detached ? $tmpFileSignedDataPath : $tmpFileContentDataPath,
                encoding: OPENSSL_ENCODING_DER,
            );

            return $res;
        } finally {
            // Close/remove temp files, even when errored
            $this->tempFileService->closeTempFile($tmpFileSignedData);
            $this->tempFileService->closeTempFile($tmpFileContentData);
            $this->tempFileService->closeTempFile($tmpFileCertificateData);
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
