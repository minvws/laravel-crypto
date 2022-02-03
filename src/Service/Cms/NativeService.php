<?php

namespace MinVWS\Crypto\Laravel\Service\Cms;

use MinVWS\Crypto\Laravel\CmsCryptoInterface;
use MinVWS\Crypto\Laravel\CryptoException;

class NativeService implements CmsCryptoInterface
{
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
            $inFile = tmpfile();
            if (!is_resource($inFile)) {
                throw CryptoException::encryptCannotCreateTempFile();
            }
            $inFilePath = stream_get_meta_data($inFile)['uri'];
            file_put_contents($inFilePath, $plainText);

            $outFile = tmpfile();
            if (!is_resource($outFile)) {
                throw CryptoException::encryptCannotCreateTempFile();
            }
            $outFilePath = stream_get_meta_data($outFile)['uri'];

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
            if (is_resource($inFile)) {
                fclose($inFile);
            }
            if (is_resource($outFile)) {
                fclose($outFile);
            }
        }
    }

    public function decrypt(string $cipherText): string
    {
        $outFile = $inFile = null;

        if (!is_readable($this->decryptionCertKeyPath)) {
            throw CryptoException::cannotReadFile($this->decryptionCertKeyPath);
        }

        try {
            $inFile = tmpfile();
            if (!is_resource($inFile)) {
                throw CryptoException::decryptCannotCreateTempFile();
            }
            $inFilePath = stream_get_meta_data($inFile)['uri'];
            file_put_contents($inFilePath, $cipherText);

            $outFile = tmpfile();
            if (!is_resource($outFile)) {
                throw CryptoException::decryptCannotCreateTempFile();
            }
            $outFilePath = stream_get_meta_data($outFile)['uri'];

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
            if (is_resource($inFile)) {
                fclose($inFile);
            }
            if (is_resource($outFile)) {
                fclose($outFile);
            }
        }
    }
}
