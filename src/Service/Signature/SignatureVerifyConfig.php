<?php

namespace MinVWS\Crypto\Laravel\Service\Signature;

class SignatureVerifyConfig
{
    protected $binary = false;
    protected $noVerify = false;

    public function __construct()
    {
    }

    public function setBinary(bool $binary): self
    {
        $this->binary = $binary;
        return $this;
    }

    public function setNoVerify(bool $noVerify): self
    {
        $this->noVerify = $noVerify;
        return $this;
    }

    public function getBinary(): bool
    {
        return $this->binary;
    }

    public function getNoVerify(): bool
    {
        return $this->noVerify;
    }

}