<?php
declare(strict_types = 1);

namespace Soraca\Jwt;

class Signature
{
    /**
     * 生成数据签名
     * @param array $data 待签名的数据数组
     * @param string $secret 服务器的 Secret
     * @return array 包含签名、时间戳和随机字符串的关联数组
     */
    public static function generate(array $data, string $secret) : array
    {
        $data['timestamp'] = round(microtime(true) * 1000);
        $data['nonce'] = self::Random(16);
        ksort($data);
        return [
            'signature' => hash_hmac('sha256',http_build_query($data),$secret),
            'timestamp' => $data['timestamp'],
            'nonce'     => $data['nonce']
        ];
    }

    /**
     * 验证数据签名
     * @param array $data
     * @param string $secret
     * @param string $signature
     * @return bool
     */
    public static function verify(array $data,string $secret,string $signature): bool
    {
        ksort($data);
        return hash_equals(hash_hmac('sha256',http_build_query($data),$secret),$signature);
    }

    /**
     * 生成指定长度的随机字符串
     * @param int $length 随机字符串的长度
     * @return string 生成的随机字符串
     */
    private static function random(int $length) : string
    {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $random = '';
        for ($i = 0; $i < $length; $i++) {
            $random .= $characters[rand(0,strlen($characters) -1)];
        }
        return $random;
    }
}