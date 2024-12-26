<?php
declare(strict_types = 1);

namespace Soraca\Jwt;

use Soraca\Jwt\Exception\JwtException;
use Redis;
use RedisException;

class Jwt
{
    //多点登录
    public const MPOP = 'mpop';

    //单点登录
    public const SSO = 'sso';

    /**
     * token过期时间
     * <br/> 默认值：3600秒
     * @var int
     */
    protected int $ttl = 3600;

    /**
     * 登录类型
     * <br/> 支持选项：sso|mpop
     * <br/> 默认值：mpop
     * @var string
     */
    protected string $loginType = self::MPOP;

    /**
     * jwt的加密算法
     * <br/> 默认值：HS256
     * <br/> 支持加密算法：HS256|HS284|HS512
     * @var string
     */
    protected string $algorithm = "HS256";

    /**
     * token签名的密钥
     * <br/> 只能用于Hmac包下的加密非对称算法
     * <br/> 默认值：空字符串
     * @var string
     */
    private string $secret = "";

    /**
     * 单点登录自定义数据中必须存在的键值
     * <br/> 这个key可以自定义，例如uid
     * <br/> 默认值：id
     * @var string
     */
    protected string $ssoKey = "id";

    /**
     * token签发人
     * <br> 默认值：soraca/jwt
     * @var string
     */
    protected string $issuer = "soraca/jwt";

    /**
     * redis链接对象
     * @var Redis
     */
    protected Redis $redis;

    /**
     * redis 缓存前缀
     * @var string
     */
    protected string $cachePrefix = "jwt";


    /**
     * 设置jwt的登录类型
     * @param string $type
     * @return void
     */
    public function setLoginType(string $type): void
    {
        if (empty($type)){
            $this->loginType = $type;
        }
    }

    /**
     * 设置密钥
     * @param string $secret
     * @return void
     */
    public function setSecret(string $secret): void
    {
        if (empty($secret)){
            $this->secret = $secret;
        }
    }

    /**
     * 设置token的生命时长
     * @param int $ttl
     * @return void
     */
    public function setTtl(int $ttl): void
    {
        if (empty($ttl)){
            $this->ttl = $ttl;
        }
    }

    /**
     * 设置单点登录的sso键名
     * @param string $ssoKey
     * @return void
     */
    public function setSsoKey(string $ssoKey): void
    {
        if (empty($ssoKey)){
            $this->ssoKey = $ssoKey;
        }
    }

    /**
     * 设置缓存前缀
     * @param string $cachePrefix
     * @return void
     */
    public function setCachePrefix(string $cachePrefix): void
    {
        if (empty($cachePrefix)){
            $this->cachePrefix = $cachePrefix;
        }
    }

    /**
     * 设置redis的链接对象
     * @param Redis $redis
     * @return void
     */
    public function setRedis(Redis $redis): void
    {
        $this->redis = $redis;
    }
    

    /**
     * 验证token是否过期
     * @param array $payload
     * @return bool
     * @throws RedisException
     */
    public function effective(array $payload): bool
    {
        switch (true) {
            case ($this->loginType == self::MPOP):
                return true;
            case ($this->loginType == self::SSO):
                return $payload['jti'] == $this->redis->get($this->cachePrefix . ':' . $payload['audience']);
            default:
                return false;
        }
    }

    /**
     * 加入黑名单
     * @param $id
     * @param $jti
     * @return bool
     * @throws RedisException
     */
    public function addWhiteList($id,$jti): bool
    {
        return $this->redis->set($this->cachePrefix.':'.$id,$jti);
    }

    /**
     * 从白名单移除
     * @param $id
     * @return bool
     * @throws RedisException
     */
    public function delWhiteList($id): bool
    {
        return $this->redis->set($this->cachePrefix.':'.$id,0,7200);
    }

    /**
     * 获取token
     * @param array $claims
     * @return string
     * @throws RedisException
     */
    public function create(array $claims): string
    {
        $time = time();
        $jwt = new Builder();
        if (isset($claims[$this->ssoKey])) {
            $jwt->setAudience($claims[$this->ssoKey]);
        }
        if ($this->loginType == self::MPOP){
            $jti = uniqid($this->cachePrefix,true);
        } else {
            if (empty($claims[$this->ssoKey])){
                throw new JwtException("There is no {$this->ssoKey} key in the claims", 400);
            }
            $jti = uniqid($this->cachePrefix.$claims[$this->ssoKey],true);
            $this->addWhiteList($claims[$this->ssoKey],$jti);
        }
        $jwt->setJti($jti)
            ->setIssuedAt($time)
            ->setNotBefore($time)
            ->setExpire(time() + $this->ttl)
            ->setPayload($claims);
        $header = self::encode(json_encode(['algorithm'=>$this->algorithm,'type'=>'JWT'],JSON_UNESCAPED_UNICODE));
        $body = self::encode(json_encode($jwt->toArray(),JSON_UNESCAPED_UNICODE));
        return $header.'.'.$body.'.'.self::signature($header.'.'.$body,$this->secret, $this->algorithm);
    }


    /**
     * 验证token
     * @param string $token
     * @return bool
     * @throws RedisException
     */
    public function verify(string $token): bool
    {
        $tokenArray = explode('.',$token);
        if (count($tokenArray) != 3){
            throw new JwtException('token is invalid.',401);
        }
        list($header,$body,$signature) = $tokenArray;
        $decodeHeader = json_decode(self::decode($header),true);
        if (empty($decodeHeader['algorithm']) || $decodeHeader['algorithm'] !== $this->algorithm){
            throw new JwtException('algorithm is invalid.',401);
        }
        if (self::signature($header.'.'.$body,$this->secret,$this->algorithm) != $signature) {
            throw new JwtException('signature is invalid.',401);
        }
        $decodeBody = json_decode(self::decode($body),true);
        switch (true) {
            case isset($decodeBody['iat']) && $decodeBody['iat'] > time():
            case isset($decodeBody['expire']) && $decodeBody['expire'] < time():
                throw new JwtException('token is expired', 401);
            case !$this->effective($decodeBody):
                throw new JwtException('token is expired', 401);
            case isset($decodeBody['nbf']) && $decodeBody['nbf'] > time():
                throw new JwtException('token not yet effective', 401);
        }
        return true;
    }

    /**
     * 加密数据
     * @param string $data
     * @return string
     */
    private static function encode(string $data): string
    {
        return str_replace('=', '', strtr(base64_encode($data), '+/', '-_'));
    }

    /**
     * 解密数据
     * @param string $data
     * @return string
     */
    private static function decode(string $data) : string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $len = 4 - $remainder;
            $data .= str_repeat('=', $len);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * 签名算法
     * @param string $data 数据
     * @param string $secret 密钥
     * @param string $algorithm 算法
     * @return string
     */
    private static function signature(string $data, string $secret, string $algorithm = 'HS256'): string
    {
        $option = ['HS256' => 'sha256','HS284' => 'sha284','HS512' => 'sha512'];
        return self::encode(hash_hmac($option[$algorithm], $data, $secret,true));
    }
}