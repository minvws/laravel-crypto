<?php

namespace MinVWS\Crypto\Laravel\Service\Signature;

use MinVWS\Crypto\Laravel\Exceptions\CryptoException;
use MinVWS\Crypto\Laravel\SignatureCryptoInterface;
use MinVWS\Crypto\Laravel\TempFileInterface;
use Symfony\Component\Process\Process;

class ProcessSpawnService implements SignatureCryptoInterface
{
    protected string $signingCertPath;
    protected string $privKeyPath;
    protected string $privKeyPass;
    protected string $certChainPath;
    protected TempFileInterface $tempFileService;

    /**
     * ProcessSpawnService constructor.
     *
     * @param string|null $signingCertPath
     * @param string|null $privKeyPath
     * @param string|null $privKeyPass
     * @param string|null $certChainPath
     * @param TempFileInterface|null $tempFileService
     */
    public function __construct(
        ?string $signingCertPath = null,                // Certificate to sign with
        ?string $privKeyPath = null,                    // Private key of the certificate
        ?string $privKeyPass = null,                    // Optional pass phrase of the key
        ?string $certChainPath = null,                  // Optional certificate chain that should be included
        //   in the signature
        ?TempFileInterface $tempFileService = null,     // Service to store temporary files
    ) {
        $this->signingCertPath = $signingCertPath ?? '';
        $this->privKeyPath = $privKeyPath ?? '';
        $this->privKeyPass = $privKeyPass ?? '';
        $this->certChainPath = $certChainPath ?? '';
        $this->tempFileService = $tempFileService ?? app(TempFileInterface::class);
    }

    /**
     * @param string $payload
     * @param bool $detached
     * @return string
     */
    public function sign(string $payload, bool $detached = false): string
    {
        if (!is_readable($this->signingCertPath)) {
            throw CryptoException::cannotReadFile($this->signingCertPath);
        }
        if (!is_readable($this->privKeyPath)) {
            throw CryptoException::cannotReadFile($this->privKeyPath);
        }
        if (!empty($this->certChainPath) && !is_readable($this->certChainPath)) {
            throw CryptoException::cannotReadFile($this->certChainPath);
        }

        $args = [
            'openssl', 'cms', '-sign',
            '-signer', $this->signingCertPath,
            '-inkey', $this->privKeyPath,
            '-outform', 'DER'
        ];
        if (!$detached) {
            $args = array_merge($args, ['-nodetach']);
        }
        if (!empty($this->privKeyPass)) {
            $args = array_merge($args, ['-passin', $this->privKeyPass]);
        }
        if (!empty($this->certChainPath)) {
            $args = array_merge($args, ['-certfile', $this->certChainPath]);
        }

        $process = new Process($args);
        $process->setInput($payload);
        $process->run();

        $errOutput = $process->getErrorOutput();
        if (!empty($errOutput)) {
            throw CryptoException::sign($errOutput);
        }

        return base64_encode($process->getOutput());
    }

    /**
     * @param string $signedPayload                         The payload with signature
     * @param string|null $content                          The actual content to verify against
     * @param string|null $detachedCertificate              Additional certificate to verify against (in case you
     *                                                        don't want to use the certificate in the signature itself)
     * @param SignatureVerifyConfig|null $verifyConfig      Additional configuration for the verification
     * @return bool
     */
    public function verify(
        string $signedPayload,
        string $content = null,
        string $detachedCertificate = null,
        ?SignatureVerifyConfig $verifyConfig = null
    ): bool {
        $tmpFile = null;
        $certTmpFile = null;

        try {
            $args = array_merge([
                'openssl', 'cms', '-verify',
                '-inform', 'DER',
                '-noout',
            ], $this->getOpenSslTags($verifyConfig));

            if (!empty($this->certChainPath)) {
                $args = array_merge($args, ['-CAfile', $this->certChainPath]);
            }

            if ($content !== null) {
                $tmpFile = $this->tempFileService->createTempFileWithContent($content);
                $args = array_merge($args, ['-content', $this->tempFileService->getTempFilePath($tmpFile)]);
            }

            if ($detachedCertificate !== null) {
                $certTmpFile = $this->tempFileService->createTempFileWithContent($detachedCertificate);
                $args = array_merge(
                    $args,
                    [
                        '-certfile',
                        $this->tempFileService->getTempFilePath($certTmpFile),
                        '-nointern',
                    ],
                );
            }

            $process = new Process($args);
            $process->setInput(base64_decode($signedPayload));
            $process->run();

            $errOutput = $process->getErrorOutput();

            // Successful and failure are expected.
            if (
                !empty($errOutput)
                && !str_contains($errOutput, "Verification successful")
                && !str_contains($errOutput, "Verification failure")
            ) {
                throw CryptoException::verify($errOutput);
            }

            return $process->getExitCode() === 0;
        } finally {
            $this->tempFileService->closeTempFile($tmpFile);
            $this->tempFileService->closeTempFile($certTmpFile);
        }
    }

    protected function getOpenSslTags(?SignatureVerifyConfig $config): array
    {
        $flags = [];
        if ($config?->getBinary()) {
            $flags[] = '-binary';
        }
        if ($config?->getNoVerify()) {
            // When we supply a cert chain, then we want to check the ca certificate chain as well by using
            // the "-purpose any" option to openssl. If there is no cert chain, we can use the "-noverify" option to
            // keep it compatible with the native PHP implementation that doesn't understand the "-purpose any" option.
            if ($this->certChainPath) {
                $flags[] = '-purpose';
                $flags[] = 'any';
            } else {
                $flags[] = '-noverify';
            }
        }

        return $flags;
    }
}
