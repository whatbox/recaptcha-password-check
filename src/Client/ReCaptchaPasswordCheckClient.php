<?php

declare(strict_types=1);

namespace ReCaptcha\PasswordCheck\Client;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use ReCaptcha\PasswordCheck\PasswordCheckResult;
use ReCaptcha\PasswordCheck\PasswordCheckVerification;

class ReCaptchaPasswordCheckClient
{
    private const DEFAULT_ENDPOINT = 'https://recaptchaenterprise.googleapis.com/v1';

    private readonly ClientInterface $httpClient;
    private readonly string $endpoint;
    private readonly string $projectId;
    private readonly string $apiKey;

    public function __construct(
        string $projectId,
        #[\SensitiveParameter] string $apiKey,
        ?ClientInterface $httpClient = null,
        string $endpoint = self::DEFAULT_ENDPOINT
    ) {
        $this->projectId = $projectId;
        $this->apiKey = $apiKey;
        $this->endpoint = rtrim($endpoint, '/');
        $this->httpClient = $httpClient ?? new Client(['base_uri' => $this->endpoint . '/']);
    }

    /**
     * @throws GuzzleException
     */
    public function checkPassword(
        string $username,
        #[\SensitiveParameter] string $password,
        string $expectedAction = 'login',
        array $eventOverrides = []
    ): PasswordCheckResult {
        $verification = PasswordCheckVerification::create($username, $password);

        return $this->completeVerification($verification, $expectedAction, $eventOverrides);
    }

    /**
     * @throws GuzzleException
     */
    public function completeVerification(
        PasswordCheckVerification $verification,
        string $expectedAction = 'login',
        array $eventOverrides = []
    ): PasswordCheckResult {
        $uri = sprintf('projects/%s/assessments?key=%s', $this->projectId, $this->apiKey);
        $payload = $this->buildAssessmentPayload($verification, $expectedAction, $eventOverrides);
        $response = $this->httpClient->request('POST', $uri, ['json' => $payload]);
        $body = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        $verificationSection = $body['privatePasswordLeakVerification'] ?? [];
        $reencrypted = self::decodeField($verificationSection['reencryptedUserCredentialsHash'] ?? null);
        $prefixes = [];
        foreach ($verificationSection['encryptedLeakMatchPrefixes'] ?? [] as $prefix) {
            $decoded = self::decodeField($prefix);
            if ($decoded !== null) {
                $prefixes[] = $decoded;
            }
        }

        if ($reencrypted === null) {
            throw new \RuntimeException('Google response is missing reencryptedUserCredentialsHash');
        }

        return $verification->verify($reencrypted, $prefixes);
    }

    private function buildAssessmentPayload(
        PasswordCheckVerification $verification,
        string $expectedAction,
        array $eventOverrides
    ): array {
        $event = array_merge([ 'expectedAction' => $expectedAction ], $eventOverrides);

        return [
            'event' => $event,
            'privatePasswordLeakVerification' => [
                'lookupHashPrefix' => base64_encode($verification->getLookupHashPrefix()),
                'encryptedUserCredentialsHash' => base64_encode($verification->getEncryptedUserCredentialsHash()),
            ],
        ];
    }

    private static function decodeField(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $decoded = base64_decode($value, true);
        if ($decoded === false) {
            return null;
        }

        return $decoded;
    }
}
