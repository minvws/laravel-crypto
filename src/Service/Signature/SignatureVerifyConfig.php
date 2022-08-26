<?php

namespace MinVWS\Crypto\Laravel\Service\Signature;

class SignatureVerifyConfig
{
    protected $binary = false;
    protected $noVerify = false;

    public function __construct()
    {
    }

    protected function setBinary(bool $binary): self
    {
        $this->binary = $binary;
        return $this;
    }

    protected function setNoVerify(bool $noVerify): self
    {
        $this->noVerify = $noVerify;
        return $this;
    }

    protected function getBinary(): bool
    {
        return $this->binary;
    }

    protected function getNoVerify(): bool
    {
        return $this->noVerify;
    }

}