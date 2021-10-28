<?php

namespace MinVWS\Crypto\Laravel\Http\Middleware;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Closure;
use MinVWS\Crypto\Laravel\SignatureCryptoInterface;

class CmsSignature
{
    public const FORMAT_NONE = "none";
    public const FORMAT_INLINE = "inline";

    protected const HEADER_CMS_SIGNATURE = 'x-cms-signed';

    /** @var SignatureCryptoInterface */
    protected $signatureService;

    /** @var string */
    protected $format = "inline";

    /**
     * CmsSignature constructor.
     * @param SignatureCryptoInterface $signatureService
     * @param string $format
     */
    public function __construct(SignatureCryptoInterface $signatureService, string $format = self::FORMAT_INLINE)
    {
        $this->signatureService = $signatureService;
        $this->format = $format;
    }

    /**
     * @param Request $request
     * @param Closure $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

        $data = trim($response->getContent());
        $signature = $this->signatureService->sign($data);

        if ($this->format == self::FORMAT_INLINE) {
            if ($response instanceof JsonResponse) {
                $response->setData(["signature" => $signature, "payload" => base64_encode($data)]);
                $response->header(self::HEADER_CMS_SIGNATURE, 'True');
            } else {
                $response->header(self::HEADER_CMS_SIGNATURE, 'False');
            }

            return $response;
        }

        return $response->header(self::HEADER_CMS_SIGNATURE, 'False');
    }
}
