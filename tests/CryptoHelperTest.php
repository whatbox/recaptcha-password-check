<?php

declare(strict_types=1);

namespace ReCaptcha\PasswordCheck\Tests;

use PHPUnit\Framework\TestCase;
use ReCaptcha\PasswordCheck\Utils\CryptoHelper;

class CryptoHelperTest extends TestCase
{
    public function testCanonicalizeUsername(): void
    {
        $this->assertSame('foo', CryptoHelper::canonicalizeUsername('Foo@example.com'));
        $this->assertSame('barbaz', CryptoHelper::canonicalizeUsername('Bar.Baz'));
    }

    public function testHashUsernameDeterministic(): void
    {
        $hash1 = CryptoHelper::hashUsername('user');
        $hash2 = CryptoHelper::hashUsername('user');
        $this->assertSame($hash1, $hash2);
        $this->assertNotSame($hash1, CryptoHelper::hashUsername('another'));
    }

    public function testBucketizeUsernameLength(): void
    {
        $prefix = CryptoHelper::bucketizeUsername('user', 13);
        $this->assertSame((int) ceil(13 / 8), strlen($prefix));
    }

    public function testHashUsernamePasswordPairProduces32Bytes(): void
    {
        $hash = CryptoHelper::hashUsernamePasswordPair('user', 'secure-password');
        $this->assertSame(32, strlen($hash));
        $this->assertSame($hash, CryptoHelper::hashUsernamePasswordPair('user', 'secure-password'));
    }
}
