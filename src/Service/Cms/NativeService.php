<?php

namespace MinVWS\Crypto\Laravel\Service\Cms;

use MinVWS\Crypto\Laravel\CmsCryptoInterface;
use MinVWS\Crypto\Laravel\Exceptions\CryptoException;
use MinVWS\Crypto\Laravel\TempFileInterface;

class NativeService implements CmsCryptoInterface
{
    /**
     * @var string[] The certificate paths that are used to encrypt the data. The privkey of any of these certs can
     * decrypt the data. Useful when you want to decrypt the same data at multiple places. */
    protected array $encryptionCertsPath;

    /**
     * @var string Single certificate path used for decrypting the data. The data could be encrypted for multiple
     * certs, but this software only will use this cert to (try to) decode.
     */
    protected string $decryptionCertPath;

    /** @var string Path to private key of the $decryptionCert certificate. Needed to decrypt the actual data. */
    protected string $decryptionCertKeyPath;

    protected TempFileInterface $tempFileService;

    /**
     * @param array $encryptionCertsPath
     * @param string $decryptionCertPath
     * @param string $decryptionCertKeyPath
     * @param TempFileInterface $tempFileService
     */
    public function __construct(
        array $encryptionCertsPath,
        string $decryptionCertPath,
        string $decryptionCertKeyPath,
        TempFileInterface $tempFileService
    ) {
        // All path names should be prefixed with file://
        $paths = [];
        foreach ($encryptionCertsPath as $p) {
            $paths[] = "file://" . $p;
        }
        $this->encryptionCertsPath = $paths;
        $this->decryptionCertPath = "file://" . $decryptionCertPath;
        $this->decryptionCertKeyPath = "file://" . $decryptionCertKeyPath;
        $this->tempFileService = $tempFileService;
    }

    public function encrypt(string $plainText): string
    {
        $outFile = $inFile = null;

        try {
            $inFile = $this->tempFileService->createTempFileWithContent($plainText);
            $inFilePath = $this->tempFileService->getTempFilePath($inFile);

            $outFile = $this->tempFileService->createTempFile();
            $outFilePath = $this->tempFileService->getTempFilePath($outFile);

            $headers = array();

            openssl_cms_encrypt(
                input_filename: $inFilePath,
                output_filename: $outFilePath,
                certificate: $this->encryptionCertsPath,
                headers: $headers,
                flags: OPENSSL_CMS_NOVERIFY,
                encoding: OPENSSL_ENCODING_PEM,
                cipher_algo: OPENSSL_CIPHER_AES_256_CBC
            );

            // Grab signature contents
            $cipherText = file_get_contents($outFilePath);
            if ($cipherText === false) {
                throw CryptoException::encrypt("could not read encrypted data from disk");
            }

            return $cipherText;
        } finally {
            $this->tempFileService->closeTempFile($inFile);
            $this->tempFileService->closeTempFile($outFile);
        }
    }

    public function decrypt(string $cipherText): string
    {
        $outFile = $inFile = null;

        if (!is_readable($this->decryptionCertPath)) {
            throw CryptoException::cannotReadFile($this->decryptionCertPath);
        }
        if (!is_readable($this->decryptionCertKeyPath)) {
            throw CryptoException::cannotReadFile($this->decryptionCertKeyPath);
        }

        try {
            $inFile = $this->tempFileService->createTempFileWithContent($cipherText);
            $inFilePath = $this->tempFileService->getTempFilePath($inFile);

            $outFile = $this->tempFileService->createTempFile();
            $outFilePath = $this->tempFileService->getTempFilePath($outFile);

            $result = openssl_cms_decrypt(
                input_filename: $inFilePath,
                output_filename: $outFilePath,
                certificate: $this->decryptionCertPath,
                private_key: $this->decryptionCertKeyPath,
                encoding: OPENSSL_ENCODING_PEM
            );
            if (!$result) {
                throw CryptoException::decrypt("could not decrypt data");
            }

            // Grab signature contents
            $plainText = file_get_contents($outFilePath);
            if ($plainText === false) {
                throw CryptoException::decrypt("could not read decrypted data from disk");
            }

            return $plainText;
        } finally {
            $this->tempFileService->closeTempFile($inFile);
            $this->tempFileService->closeTempFile($outFile);
        }
    }
}
