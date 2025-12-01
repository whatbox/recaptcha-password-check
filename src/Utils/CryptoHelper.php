<?php

declare(strict_types=1);

namespace ReCaptcha\PasswordCheck\Utils;

final class CryptoHelper
{
    private const PASSWORD_HASH_CONSTANT_SALT = "\x30\x76\x2A\xD2\x3F\x7B\xA1\x9B\xF8\xE3\x42\xFC\xA1\xA7\x8D\x06\xE6\x6B\xE4\xDB\xB8\x4F\x81\x53\xC5\x03\xC8\xDB\xBD\xDE\xA5\x20";
    private const USERNAME_HASH_CONSTANT_SALT = "\xC4\x94\xA3\x95\xF8\xC0\xE2\x3E\xA9\x23\x04\x78\x70\x2C\x72\x18\x56\x54\x99\xB3\xE9\x21\x18\x6C\x21\x1A\x01\x22\x3C\x45\x4A\xFA";

    private const SCRYPT_CPU_MEM_COST = 4096; // N
    private const SCRYPT_BLOCK_SIZE = 8;      // r
    private const SCRYPT_PARALLELIZATION = 1; // p
    private const SCRYPT_KEY_LENGTH = 32;

    private function __construct()
    {
    }

    public static function canonicalizeUsername(string $username): string
    {
        $username = strtolower($username);
        if (($at = strrpos($username, '@')) !== false) {
            $username = substr($username, 0, $at);
        }

        return str_replace('.', '', $username);
    }

    public static function hashUsername(string $canonicalizedUsername): string
    {
        $usernameBytes = self::encodeUtf8($canonicalizedUsername);
        return hash('sha256', $usernameBytes . self::USERNAME_HASH_CONSTANT_SALT, binary: true);
    }

    public static function hashUsernamePasswordPair(string $canonicalizedUsername, #[\SensitiveParameter] string $password): string
    {
        $usernameBytes = self::encodeUtf8($canonicalizedUsername);
        $passwordBytes = self::encodeUtf8($password);
        $hashInput = $usernameBytes . $passwordBytes;
        $saltInput = $usernameBytes . self::PASSWORD_HASH_CONSTANT_SALT;

        // Fast path using https://pecl.php.net/package/scrypt if available
        if (extension_loaded('scrypt')) {
            return hex2bin(scrypt(
                $hashInput,
                $saltInput,
                self::SCRYPT_CPU_MEM_COST,
                self::SCRYPT_BLOCK_SIZE,
                self::SCRYPT_PARALLELIZATION,
                self::SCRYPT_KEY_LENGTH
            ));
        } else {
            return self::scrypt($hashInput, $saltInput, self::SCRYPT_KEY_LENGTH);
        }
    }

    public static function bucketizeUsername(string $canonicalizedUsername, int $allowedPrefixLength): string
    {
        return BitPrefix::fromBytes(self::hashUsername($canonicalizedUsername), $allowedPrefixLength)->getPrefix();
    }

    private static function encodeUtf8(string $value): string
    {
        return mb_convert_encoding($value, 'UTF-8', 'UTF-8');
    }

    private static function scrypt(
        #[\SensitiveParameter] string $password,
        string $salt,
        int $keyLength
    ): string {
        $blockSize = 128 * self::SCRYPT_BLOCK_SIZE;
        $initial = self::pbkdf2($password, $salt, 1, $blockSize * self::SCRYPT_PARALLELIZATION);
        $blocks = str_split($initial, $blockSize);
        foreach ($blocks as &$block) {
            $block = self::romix($block, self::SCRYPT_CPU_MEM_COST, self::SCRYPT_BLOCK_SIZE);
        }
        unset($block);
        $derivedSalt = implode('', $blocks);

        return self::pbkdf2($password, $derivedSalt, 1, $keyLength);
    }

    private static function pbkdf2(
        #[\SensitiveParameter] string $password,
        string $salt,
        int $iterations,
        int $length
    ): string {
        return hash_pbkdf2('sha256', $password, $salt, $iterations, $length, true);
    }

    private static function romix(string $block, int $N, int $r): string
    {
        $X = $block;
        $V = [];
        for ($i = 0; $i < $N; $i++) {
            $V[$i] = $X;
            $X = self::blockMix($X, $r);
        }
        for ($i = 0; $i < $N; $i++) {
            $j = self::integerify($X, $r) & ($N - 1);
            $X = $X ^ $V[$j];
            $X = self::blockMix($X, $r);
        }

        return $X;
    }

    private static function integerify(string $block, int $r): int
    {
        $lastChunk = substr($block, (2 * $r - 1) * 64, 64);
        $parts = unpack('V2', substr($lastChunk, 0, 8));
        return (int) ($parts[1] + ($parts[2] << 32));
    }

    private static function blockMix(string $block, int $r): string
    {
        $X = substr($block, (2 * $r - 1) * 64, 64);
        $Y = array_fill(0, 2 * $r, '');
        for ($i = 0; $i < 2 * $r; $i++) {
            $chunk = substr($block, $i * 64, 64);
            $X = self::salsa208(self::xorChunk($X, $chunk));
            $index = $i % 2 === 0 ? $i / 2 : $r + intdiv($i - 1, 2);
            $Y[$index] = $X;
        }

        return implode('', $Y);
    }

    private static function xorChunk(string $a, string $b): string
    {
        return $a ^ $b;
    }

    private static function salsa208(string $input): string
    {
        $state = array_values(unpack('V16', $input));
        $working = $state;
        for ($round = 0; $round < 8; $round += 2) {
            // Column rounds
            $working[4] ^= self::rotl32($working[0] + $working[12], 7);
            $working[8] ^= self::rotl32($working[4] + $working[0], 9);
            $working[12] ^= self::rotl32($working[8] + $working[4], 13);
            $working[0] ^= self::rotl32($working[12] + $working[8], 18);

            $working[9] ^= self::rotl32($working[5] + $working[1], 7);
            $working[13] ^= self::rotl32($working[9] + $working[5], 9);
            $working[1] ^= self::rotl32($working[13] + $working[9], 13);
            $working[5] ^= self::rotl32($working[1] + $working[13], 18);

            $working[14] ^= self::rotl32($working[10] + $working[6], 7);
            $working[2] ^= self::rotl32($working[14] + $working[10], 9);
            $working[6] ^= self::rotl32($working[2] + $working[14], 13);
            $working[10] ^= self::rotl32($working[6] + $working[2], 18);

            $working[3] ^= self::rotl32($working[15] + $working[11], 7);
            $working[7] ^= self::rotl32($working[3] + $working[15], 9);
            $working[11] ^= self::rotl32($working[7] + $working[3], 13);
            $working[15] ^= self::rotl32($working[11] + $working[7], 18);

            // Row rounds
            $working[1] ^= self::rotl32($working[0] + $working[3], 7);
            $working[2] ^= self::rotl32($working[1] + $working[0], 9);
            $working[3] ^= self::rotl32($working[2] + $working[1], 13);
            $working[0] ^= self::rotl32($working[3] + $working[2], 18);

            $working[6] ^= self::rotl32($working[5] + $working[4], 7);
            $working[7] ^= self::rotl32($working[6] + $working[5], 9);
            $working[4] ^= self::rotl32($working[7] + $working[6], 13);
            $working[5] ^= self::rotl32($working[4] + $working[7], 18);

            $working[11] ^= self::rotl32($working[10] + $working[9], 7);
            $working[8] ^= self::rotl32($working[11] + $working[10], 9);
            $working[9] ^= self::rotl32($working[8] + $working[11], 13);
            $working[10] ^= self::rotl32($working[9] + $working[8], 18);

            $working[12] ^= self::rotl32($working[15] + $working[14], 7);
            $working[13] ^= self::rotl32($working[12] + $working[15], 9);
            $working[14] ^= self::rotl32($working[13] + $working[12], 13);
            $working[15] ^= self::rotl32($working[14] + $working[13], 18);
        }

        for ($i = 0; $i < 16; $i++) {
            $working[$i] = ($working[$i] + $state[$i]) & 0xFFFFFFFF;
        }

        return pack('V16', ...$working);
    }

    private static function rotl32(int $value, int $count): int
    {
        $value &= 0xFFFFFFFF;
        return (($value << $count) | ($value >> (32 - $count))) & 0xFFFFFFFF;
    }
}
