# Laravel crypto package

To learn more about the crypto used in the projects, please take a look at our [crypto doc](CRYPTO-README.md).

## Requirements
- PHP >= 8.0
- Laravel >= 8.0

## Installation
1. Install the package via composer:
  ```sh
  composer require minvws/laravel-crypto
  ```

2. **If you are running Laravel 5.5 or higher (the package will be auto-discovered), skip
  this step.** Find the `providers` array key in `config/app.php` and register
  the **Laravel Crypto Service Provider**:
  ```php
  'providers' => [
      ...
      MinVWS\Laravel\Providers\CryptoServiceProvider::class,
  ];
  ```

# Usage
This section describes the usage of the different crypto functionalities

## CMS Crypto

CMS crypto allows you to easily encrypt (and possibly decrypt) data.

Usage:

```php
class UserController {
    
    protected CmsCryptoInterface $service;
    
    function index()
    {
        $cipherText = $this->service->encrypt('plaintext');
        return new JsonResponse(['data' => $cipherText]);        
    }
}
```

## Sealbox Crypto

```php
class UserController {
    
    protected SealboxCryptoInterface $service;
    
    function index()
    {
        $cipherText = $this->service->encrypt('plaintext');
        return new JsonResponse(['data' => $cipherText]);        
    }
}
```

## Signatures

```php
class UserController {
    
    protected SignatureCryptoInterface $service;
    
    function index()
    {
        $sig = $this->service->sign('foobar', false);
        return new JsonResponse(['signature' => $sig]);        
    }
}
```

### Laravel HTTP Middleware

Step 1: Add to `app/Http/Kernel.php`: 

```php 
/*/ Package Middleware /*/
    ...
    'cms_sign' => \MinVWS\Crypto\Laravel\Http\Middleware\CmsSignature::class,
```

Step 2: Add your middleware to your routes:

```php 
Route::middleware('cms_sign')->post(
    '/my/route',
    [RouteController::class, 'index']
);
```

## Environment vars

    # OpenSSL CMS encryption
    CMS_ENCRYPTION_CERT_PATHS        A comma separated list of x509 certificate paths that are used for encrypting data 
    CMS_DECRYPTION_CERT_PATH         A certificate file path that is used for decrypting data (optional)  
    CMS_DECRYPTION_CERT_KEY_PATH     The key file for the cert that is used for decrypting data (optional)  

    # LibSodium sealbox
    CMS_SEAL_PRIVKEY            Our own private X25519 key
    CMS_SEAL_RECIPIENT_PUBKEY   Public X25519 key of the recipient
    
    # OpenSSL CMS signing
    CMS_SIGN_X509_CERT          The certificate file to sign the data
    CMS_SIGN_X509_KEY           The key file to sign the data
    CMS_SIGN_X509_PASS          Optional passphrase for the key file
    CMS_SIGN_X509_CHAIN         Optional chain of certificates to be added to the signed data


# Running tests

Tests are run based on your PHP version. On PHP7, openssl functionality that is not available, will not be tested.

## Running tests when you don't have PHP8 (but have docker):

You can still test PHP8 functionality when running PHP7 by using the PHP8 docker image:

    docker run -ti -w /app -v $PWD:/app php:8-cli php /app/vendor/bin/phpunit

Using code coverage on PHP8:

    docker run -ti -w /app -v $PWD:/app php:8-cli phpdbg -qrr /app/vendor/bin/phpunit --coverage-html=./html
