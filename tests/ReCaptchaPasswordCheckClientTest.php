<?php

declare(strict_types=1);

namespace ReCaptcha\PasswordCheck\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use ReCaptcha\PasswordCheck\Client\ReCaptchaPasswordCheckClient;
use ReCaptcha\PasswordCheck\Crypto\EcCommutativeCipher;
use ReCaptcha\PasswordCheck\PasswordCheckVerification;
use ReCaptcha\PasswordCheck\Utils\CryptoHelper;

class ReCaptchaPasswordCheckClientTest extends TestCase
{
    public function testCompleteVerificationParsesResponse(): void
    {
        $verification = PasswordCheckVerification::create('foo', 'bar');
        $serverCipher = EcCommutativeCipher::createWithNewKey();
        $reencrypted = $serverCipher->reEncrypt($verification->getEncryptedUserCredentialsHash());
        $hash = CryptoHelper::hashUsernamePasswordPair(CryptoHelper::canonicalizeUsername('foo'), 'bar');
        $encrypted = $serverCipher->encrypt($hash);
        $prefix = substr(hash('sha256', $encrypted, binary: true), 0, 20);

        $mockResponse = json_encode([
            'privatePasswordLeakVerification' => [
                'reencryptedUserCredentialsHash' => base64_encode($reencrypted),
                'encryptedLeakMatchPrefixes' => [base64_encode($prefix)],
            ],
        ], JSON_THROW_ON_ERROR);

        $handler = HandlerStack::create(new MockHandler([
            new Response(200, [], $mockResponse),
        ]));
        $httpClient = new Client(['handler' => $handler, 'base_uri' => 'https://example.com/v1/']);
        $client = new ReCaptchaPasswordCheckClient('project-id', 'api-key', $httpClient, 'https://example.com/v1');

        $result = $client->completeVerification($verification);
        $this->assertTrue($result->areCredentialsLeaked());
    }
}
