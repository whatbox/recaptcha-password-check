<?php

declare(strict_types=1);

namespace ReCaptcha\PasswordCheck;

class PasswordCheckResult
{
    public function __construct(
        private readonly string $username,
        private readonly bool $credentialsLeaked
    ) {
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function areCredentialsLeaked(): bool
    {
        return $this->credentialsLeaked;
    }
}
