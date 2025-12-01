<?php

declare(strict_types=1);

namespace ReCaptcha\PasswordCheck;

use ReCaptcha\PasswordCheck\Crypto\EcCommutativeCipher;
use ReCaptcha\PasswordCheck\Crypto\HashType;
use ReCaptcha\PasswordCheck\Crypto\SupportedCurve;
use ReCaptcha\PasswordCheck\Utils\CryptoHelper;

class PasswordCheckVerification
{
    private const CURVE = SupportedCurve::SECP256R1;
    private const HASH_TYPE = HashType::SHA256;
    private const USERNAME_HASH_PREFIX_LENGTH = 26;

    private function __construct(
        private readonly EcCommutativeCipher $cipher,
        private readonly string $username,
        private readonly string $encryptedUserCredentialsHash,
        private readonly string $lookupHashPrefix
    ) {
    }

    public static function create(
        string $username,
        #[\SensitiveParameter] string $password,
        ?EcCommutativeCipher $cipher = null
    ): self {
        if ($username === '') {
            throw new \InvalidArgumentException('Username cannot be null or empty');
        }
        if ($password === '') {
            throw new \InvalidArgumentException('Password cannot be null or empty');
        }

        $cipher ??= EcCommutativeCipher::createWithNewKey(self::CURVE, self::HASH_TYPE);
        $canonicalUsername = CryptoHelper::canonicalizeUsername($username);
        $hashedPair = CryptoHelper::hashUsernamePasswordPair($canonicalUsername, $password);
        $encryptedHash = $cipher->encrypt($hashedPair);
        $lookupHashPrefix = CryptoHelper::bucketizeUsername(
            $canonicalUsername,
            self::USERNAME_HASH_PREFIX_LENGTH
        );

        return new self($cipher, $username, $encryptedHash, $lookupHashPrefix);
    }

    public function verify(string $reEncryptedUserCredentialsHash, array $encryptedLeakMatchPrefixes): PasswordCheckResult
    {
        if ($reEncryptedUserCredentialsHash === '') {
            throw new \InvalidArgumentException('reEncryptedLookupHash must be present');
        }

        $serverEncrypted = $this->cipher->decrypt($reEncryptedUserCredentialsHash);
        $reHashed = hash('sha256', $serverEncrypted, binary: true);
        $credentialsLeaked = false;
        foreach ($encryptedLeakMatchPrefixes as $prefix) {
            if (!is_string($prefix)) {
                continue;
            }
            if ($prefix === '') {
                continue;
            }
            if ($this->isPrefix($reHashed, $prefix)) {
                $credentialsLeaked = true;
                break;
            }
        }

        return new PasswordCheckResult($this, $this->username, $credentialsLeaked);
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function getEncryptedUserCredentialsHash(): string
    {
        return $this->encryptedUserCredentialsHash;
    }

    public function getLookupHashPrefix(): string
    {
        return $this->lookupHashPrefix;
    }

    private function isPrefix(string $hash, string $prefix): bool
    {
        return strncmp($hash, $prefix, strlen($prefix)) === 0;
    }
}
