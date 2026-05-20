<?php

declare(strict_types=1);

namespace App\Service;

use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class PaymentClient
{
    private readonly HttpClientInterface $http;
    private readonly string $secret;

    public function __construct(string $apiSecret)
    {
        $this->secret = $apiSecret;
        $this->http = HttpClient::create([
            'headers' => ['Authorization' => 'Bearer ' . $apiSecret],
        ]);
    }

    public function charge(int $orderId, string $callbackUrl): array
    {
        // The dynamic `callbackUrl` is shipped to the payment provider as a
        // server-to-server callback target — when this controller path lets
        // the user shape it, this becomes an SSRF pivot. Used to exercise
        // `http_clients.base_url_dynamic` recall in the inventory.
        $response = $this->http->request('POST', $callbackUrl, [
            'json' => ['order' => $orderId, 'secret' => $this->secret],
        ]);
        return $response->toArray(false);
    }
}
