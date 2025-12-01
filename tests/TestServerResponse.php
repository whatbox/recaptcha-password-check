<?php

declare(strict_types=1);

namespace ReCaptcha\PasswordCheck\Tests;

use ReCaptcha\PasswordCheck\Crypto\EcCommutativeCipher;
use ReCaptcha\PasswordCheck\PasswordCheckVerification;
use ReCaptcha\PasswordCheck\Utils\CryptoHelper;

final class TestServerResponse
{
    /** @param array<int, array{username: string, password: string}> $credentials */
    public static function create(PasswordCheckVerification $verification, array $credentials): self
    {
        $serverCipher = EcCommutativeCipher::createWithNewKey();
        $reencryptedLookupHash = $serverCipher->reEncrypt($verification->getEncryptedUserCredentialsHash());
        $prefixes = [];
        foreach ($credentials as $cred) {
            $canonical = CryptoHelper::canonicalizeUsername($cred['username']);
            $hash = CryptoHelper::hashUsernamePasswordPair($canonical, $cred['password']);
            $encrypted = $serverCipher->encrypt($hash);
            $prefixes[] = substr(hash('sha256', $encrypted, binary: true), 0, 20);
        }

        return new self($reencryptedLookupHash, $prefixes);
    }

    public function __construct(
        private readonly string $serverReencryptedLookupHash,
        private readonly array $encryptedLeakMatchPrefixes
    ) {
    }

    public function getServerReencryptedLookupHash(): string
    {
        return $this->serverReencryptedLookupHash;
    }

    /** @return string[] */
    public function getEncryptedLeakMatchPrefixes(): array
    {
        return $this->encryptedLeakMatchPrefixes;
    }
}
