<?php

namespace Katuva;

class TripleSec
{
    const MAGIC_BYTES = [0x1c, 0x94, 0xd7, 0xde];
    const VERSION     = [0x00, 0x00, 0x00, 0x04];

    const SALT_LENGTH = 16;

    const SCRYPT_N = 2 ** 15;
    const SCRYPT_R = 8;
    const SCRYPT_P = 1;

    const SHA512_KEY_SIZE    = 48;
    const SHA512_OUTPUT_SIZE = 64;
    const SHA512_BLOCK_SIZE  = 128;
    const SHA3_KEY_SIZE      = 48;
    const SHA3_OUTPUT_SIZE   = 64;
    const SHA3_BLOCK_SIZE    = 72;

    const XSALSA20_IV_SIZE  = 24;
    const XSALSA20_KEY_SIZE = 32;
    CONST AES_IV_SIZE       = 16;
    const AES_KEY_SIZE      = 32;

    // order is important!
    protected static $keySizes = [
        'sha512'   => self::SHA512_KEY_SIZE,
        'sha3'     => self::SHA3_KEY_SIZE,
        'aes'      => self::AES_KEY_SIZE,
        'xsalsa20' => self::XSALSA20_KEY_SIZE,
    ];

    /**
     * @param int $numBytes
     * @return string
     * @throws \Exception
     */
    protected static function getRandomBytes(int $numBytes): string
    {
        return random_bytes($numBytes);
    }

    protected static function compare(string $str1, string $str2)
    {
        return hash_equals($str1, $str2);
    }

    protected static function hmac(string $data, string $key, callable $algoFn, int $algoBlockSizeInBytes): string
    {
        if (strlen($key) > $algoBlockSizeInBytes)
        {
            $key = $algoFn($key); // keys longer than blocksize are shortened
        }

        if (strlen($key) < $algoBlockSizeInBytes)
        {
            $key = $key . str_repeat(chr(0x00), $algoBlockSizeInBytes - strlen($key)); // keys shorter than blocksize are zero-padded
        }

        $outerKeyPad = str_repeat(chr(0x5c), $algoBlockSizeInBytes) ^ $key;
        $innerKeyPad = str_repeat(chr(0x36), $algoBlockSizeInBytes) ^ $key;

        return $algoFn($outerKeyPad . $algoFn($innerKeyPad . $data));
    }

    protected static function sha512hmac($data, $key)
    {
        $hashFn = function ($data) { return hash('sha512', $data, true); };

        return static::hmac($data, $key, $hashFn, static::SHA512_BLOCK_SIZE);
    }

    protected static function sha3hmac($data, $key)
    {
        $hashFn = function ($data) { return hash('sha3-512', $data, true); };

        return static::hmac($data, $key, $hashFn, static::SHA3_BLOCK_SIZE);
    }

    protected static function xsalsa20Encrypt(string $str, string $key, string $iv): string
    {
        return $iv . sodium_crypto_stream_xor($str, $iv, $key);
    }

    protected static function xsalsa20Decrypt(string $str, string $key): string
    {
        $iv  = substr($str, 0, static::XSALSA20_IV_SIZE);
        $str = substr($str, static::XSALSA20_IV_SIZE);

        return sodium_crypto_stream_xor($str, $iv, $key);
    }

    protected static function aesEncrypt(string $str, string $key, string $iv): string
    {
        return $iv . openssl_encrypt($str, 'aes-256-ctr', $key, OPENSSL_RAW_DATA, $iv);
    }

    protected static function aesDecrypt(string $str, string $key): string
    {
        $iv  = substr($str, 0, static::AES_IV_SIZE);
        $str = substr($str, static::AES_IV_SIZE);

        return openssl_decrypt($str, 'aes-256-ctr', $key, OPENSSL_RAW_DATA, $iv);
    }

    protected static function getStretchedKeys($key, $salt)
    {
        $totalSize   = array_sum(static::$keySizes);
        $keyMaterial = sodium_hex2bin(scrypt($key, $salt, static::SCRYPT_N, static::SCRYPT_R, static::SCRYPT_P, $totalSize));
        if (strlen($keyMaterial) != $totalSize)
        {
            throw new \RuntimeException('scrypt returned the wrong number of bytes');
        }

        $keys = [];
        foreach (static::$keySizes as $algo => $keySize)
        {
            $keys[$algo] = substr($keyMaterial, 0, $keySize);
            $keyMaterial = substr($keyMaterial, $keySize);
        }

        return $keys;
    }

    public static function encrypt($plaintext, $initialKey)
    {
        $salt = static::getRandomBytes(static::SALT_LENGTH);
        $keys = static::getStretchedKeys($initialKey, $salt);

        $ivs = [
            'aes'      => static::getRandomBytes(static::AES_IV_SIZE),
            'xsalsa20' => static::getRandomBytes(static::XSALSA20_IV_SIZE)
        ];

        $header = join('', array_map('chr', array_merge(static::MAGIC_BYTES, static::VERSION)));

        $enc1 = static::xsalsa20Encrypt($plaintext, $keys['xsalsa20'], $ivs['xsalsa20']);
        $enc2 = static::aesEncrypt($enc1, $keys['aes'], $ivs['aes']);

        $toMac = $header . $salt . $enc2;
        $mac1  = static::sha512hmac($toMac, $keys['sha512']);
        $mac2  = static::sha3hmac($toMac, $keys['sha3']);

        return sodium_bin2hex($header . $salt . $mac1 . $mac2 . $enc2);
    }

    public static function decrypt($ciphertext, $initialKey)
    {
        $ciphertext = sodium_hex2bin($ciphertext);

        $header = join('', array_map('chr', array_merge(static::MAGIC_BYTES, static::VERSION)));

        $minLength = strlen($header) + static::SALT_LENGTH + static::SHA512_OUTPUT_SIZE + static::SHA3_OUTPUT_SIZE +
            static::XSALSA20_IV_SIZE + static::AES_IV_SIZE;

        if (strlen($ciphertext) < $minLength)
        {
            throw new TripleSecException('input is too short');
        }

        if (substr($ciphertext, 0, strlen($header)) !== $header)
        {
            throw new TripleSecException('invalid magic byte or version');
        }
        $ciphertext = substr($ciphertext, strlen($header));

        $salt       = substr($ciphertext, 0, static::SALT_LENGTH);
        $ciphertext = substr($ciphertext, static::SALT_LENGTH);

        $keys = static::getStretchedKeys($initialKey, $salt);

        $mac1       = substr($ciphertext, 0, static::SHA512_OUTPUT_SIZE);
        $ciphertext = substr($ciphertext, static::SHA512_OUTPUT_SIZE);

        $mac2       = substr($ciphertext, 0, static::SHA3_OUTPUT_SIZE);
        $ciphertext = substr($ciphertext, static::SHA3_OUTPUT_SIZE);

        $toMac = $header . $salt . $ciphertext;
        if (!static::compare($mac1, static::sha512hmac($toMac, $keys['sha512'])))
        {
            throw new TripleSecInvalidKeyException('sha512 hmac does not match');
        }
        if (!static::compare($mac2, static::sha3hmac($toMac, $keys['sha3'])))
        {
            throw new TripleSecInvalidKeyException('sha3 hmac does not match');
        }

        return static::xsalsa20Decrypt(static::aesDecrypt($ciphertext, $keys['aes']), $keys['xsalsa20']);
    }
}
