<?php

namespace MinVWS\Crypto\Laravel\Service\Cms;

use MinVWS\Crypto\Laravel\CmsCryptoInterface;
use MinVWS\Crypto\Laravel\Exceptions\CryptoException;
use MinVWS\Crypto\Laravel\Traits\TempFiles;

class NativeService implements CmsCryptoInterface
{
    use TempFiles;

    /**
     * @var string[] The certificate paths that are used to encrypt the data. The privkey of any of these certs can
     * decrypt the data. Useful when you want to decrypt the same data at multiple places. */
    protected $encryptionCertsPath;

    /**
     * @var string Single certificate path used for decrypting the data. The data could be encrypted for multiple
     * certs, but this software only will use this cert to (try to) decode.
     */
    protected $decryptionCertPath;

    /** @var string Path to private key of the $decryptionCert certificate. Needed to decrypt the actual data. */
    protected $decryptionCertKeyPath;

    /**
     * @param array $encryptionCertsPath
     * @param string $decryptionCertPath
     * @param string $decryptionCertKeyPath
     */
    public function __construct(array $encryptionCertsPath, string $decryptionCertPath, string $decryptionCertKeyPath)
    {
        // All path names should be prefixed with file://
        $paths = [];
        foreach ($encryptionCertsPath as $p) {
            $paths[] = "file://" . $p;
        }
        $this->encryptionCertsPath = $paths;
        $this->decryptionCertPath = "file://" . $decryptionCertPath;
        $this->decryptionCertKeyPath = "file://" . $decryptionCertKeyPath;
    }

    public function encrypt(string $plainText): string
    {
        $outFile = $inFile = null;

        try {
            $inFile = $this->createTempFileWithContent($plainText);
            $inFilePath = $this->getTempFilePath($inFile);

            $outFile = $this->createTempFile();
            $outFilePath = $this->getTempFilePath($outFile);

            $headers = array();

            openssl_cms_encrypt(
                $inFilePath,
                $outFilePath,
                $this->encryptionCertsPath,
                $headers,
                OPENSSL_CMS_NOVERIFY,
                OPENSSL_ENCODING_PEM,
                OPENSSL_CIPHER_AES_256_CBC
            );

            // Grab signature contents
            $cipherText = file_get_contents($outFilePath);
            if ($cipherText === false) {
                throw CryptoException::encrypt("could not read encrypted data from disk");
            }

            return $cipherText;
        } finally {
            $this->closeTempFile($inFile);
            $this->closeTempFile($outFile);
        }
    }

    public function decrypt(string $cipherText): string
    {
        $outFile = $inFile = null;

        if (!is_readable($this->decryptionCertKeyPath)) {
            throw CryptoException::cannotReadFile($this->decryptionCertKeyPath);
        }

        try {
            $inFile = $this->createTempFileWithContent($cipherText);
            $inFilePath = $this->getTempFilePath($inFile);

            $outFile = $this->createTempFile();
            $outFilePath = $this->getTempFilePath($outFile);

            $result = openssl_cms_decrypt(
                $inFilePath,
                $outFilePath,
                $this->decryptionCertPath,
                $this->decryptionCertKeyPath,
                OPENSSL_ENCODING_PEM
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
            $this->closeTempFile($inFile);
            $this->closeTempFile($outFile);
        }
    }
}
