<?php

declare(strict_types=1);

namespace ChernegaSergiy\XAuthConnect\Service;

use ChernegaSergiy\PhpJwtVirion\JwtHelper;

class IdTokenService
{
    private KeyService $keyService;
    private string $issuerUrl;

    public function __construct(KeyService $keyService, string $issuerUrl)
    {
        $this->keyService = $keyService;
        $this->issuerUrl = $issuerUrl;
    }

    public function createIdToken(string $username, string $clientId, int $authTime, ?string $nonce, int $expiry = 3600): string
    {
        $privateKey = $this->keyService->getPrivateKey();
        $publicKeyJwk = $this->keyService->getPublicKeyAsJwk();
        $kid = $publicKeyJwk['kid'];

        $currentTime = time();

        $payload = [
            'iss' => $this->issuerUrl,
            'sub' => $username,
            'aud' => $clientId,
            'exp' => $currentTime + $expiry,
            'iat' => $currentTime,
            'auth_time' => $authTime,
        ];

        if ($nonce !== null) {
            $payload['nonce'] = $nonce;
        }

        $jwtHelper = new JwtHelper($privateKey, 'RS256');
        return $jwtHelper->encode($payload, $kid);
    }
}
