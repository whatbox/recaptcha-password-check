<?php

declare(strict_types=1);

namespace ReCaptcha\PasswordCheck\Tests;

use PHPUnit\Framework\TestCase;
use ReCaptcha\PasswordCheck\PasswordCheckVerification;

class PasswordCheckVerificationTest extends TestCase
{
    private const TEST_USERNAME = 'foo';
    private const TEST_PASSWORD = 'bar';

    public function testCreatesVerification(): void
    {
        $verification = PasswordCheckVerification::create(self::TEST_USERNAME, self::TEST_PASSWORD);

        $this->assertSame(self::TEST_USERNAME, $verification->getUsername());
        $this->assertGreaterThan(0, strlen($verification->getEncryptedUserCredentialsHash()));
        $this->assertGreaterThan(0, strlen($verification->getLookupHashPrefix()));
    }

    public function testLeakFound(): void
    {
        $verification = PasswordCheckVerification::create(self::TEST_USERNAME, self::TEST_PASSWORD);
        $response = TestServerResponse::create($verification, [
            ['username' => self::TEST_USERNAME, 'password' => self::TEST_PASSWORD],
            ['username' => 'another', 'password' => 'pass'],
        ]);

        $result = $verification->verify($response->getServerReencryptedLookupHash(), $response->getEncryptedLeakMatchPrefixes());
        $this->assertTrue($result->areCredentialsLeaked());
    }

    public function testCanonicalizedUsernameMatches(): void
    {
        $verification = PasswordCheckVerification::create(self::TEST_USERNAME . '.user@example.com', self::TEST_PASSWORD);
        $response = TestServerResponse::create($verification, [
            ['username' => self::TEST_USERNAME . 'user', 'password' => self::TEST_PASSWORD],
        ]);

        $result = $verification->verify($response->getServerReencryptedLookupHash(), $response->getEncryptedLeakMatchPrefixes());
        $this->assertTrue($result->areCredentialsLeaked());
    }

    public function testNoLeakFound(): void
    {
        $verification = PasswordCheckVerification::create(self::TEST_USERNAME, self::TEST_PASSWORD);
        $response = TestServerResponse::create($verification, [
            ['username' => self::TEST_USERNAME, 'password' => 'different'],
        ]);

        $result = $verification->verify($response->getServerReencryptedLookupHash(), $response->getEncryptedLeakMatchPrefixes());
        $this->assertFalse($result->areCredentialsLeaked());
    }

    public function testThrowsOnEmptyInputs(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        PasswordCheckVerification::create('', self::TEST_PASSWORD);
    }
}
