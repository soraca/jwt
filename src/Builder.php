<?php
declare(strict_types = 1);

namespace Soraca\Jwt;

use ArrayAccess;

class Builder implements ArrayAccess
{
    private array $container = [];

    public function __construct(array $container = [])
    {
        $this->container = $container;
    }

    public function __get(string $key)
    {
        return $this->container[$key];
    }

    public function __set(string $key, $value)
    {
        $this->container[$key] = $value;
    }

    public function __isset(string $key)
    {
        return isset($this->container[$key]);
    }

    public function __unset(string $key)
    {
        unset($this->container[$key]);
    }

    public function offsetSet(mixed $offset, mixed $value) : void
    {
        if (is_null($offset)){
            $this->container[] = $value;
        } else {
            $this->container[$offset] = $value;
        }
    }

    public function offsetUnset(mixed $offset) : void
    {
        unset($this->container[$offset]);
    }

    public function offsetGet(mixed $offset) : mixed
    {
        return $this->container[$offset] ?? null;
    }

    public function offsetExists(mixed $offset) : bool
    {
        return isset($this->container[$offset]);
    }

    public function toArray(): array
    {
        return $this->container;
    }

    /**
     * 设置签发者
     * @param string $scope
     * @return $this
     */
    public function setIssuer(string $scope): static
    {
        $this->container['issuer'] = $scope;
        return $this;
    }

    /**
     * 获取签发者
     * @return string
     */
    public function getIssuer() : string
    {
        return $this->container['issuer'] ?? '';
    }

    /**
     * 设置接收人
     * @param $audience
     * @return $this
     */
    public function setAudience($audience): static
    {
        $this->container['audience'] = $audience;
        return $this;
    }

    /**
     * 获取接收人
     * @return string
     */
    public function getAudience(): string
    {
        return $this->container['audience'] ?? '';
    }

    /**
     * 设置token的生命时间
     * @param int $expire
     * @return $this
     */
    public function setExpire(int $expire): static
    {
        $this->container['expire'] = $expire;
        return $this;
    }

    /**
     * 获取token的生命时间
     * @return int
     */
    public function getExpire(): int
    {
        return $this->container['expire'] ?? 0;
    }

    /**
     * 设置token的生效时间戳
     * @param int $notBefore
     * @return $this
     */
    public function setNotBefore(int $notBefore): static
    {
        $this->container['nbf'] = $notBefore;
        return $this;
    }

    /**
     * 获取token的生效时间戳
     * @return int
     */
    public function getNotBefore(): int
    {
        return $this->container['nbf'] ?? 0;
    }

    /**
     * 设置签发时间
     * @param int $issuedAt
     * @return $this
     */
    public function setIssuedAt(int $issuedAt): static
    {
        $this->container['iat'] = $issuedAt;
        return $this;
    }

    /**
     * 获取签发时间
     * @return int
     */
    public function getIssuedAt(): int
    {
        return $this->container['iat'] ?? 0;
    }

    /**
     * 设置token的唯一标识
     * @param string $jti
     * @return $this
     */
    public function setJti(string $jti): static
    {
        $this->container['jti'] = $jti;
        return $this;
    }

    /**
     * 获取token的唯一标识
     * @return string
     */
    public function getJti(): string
    {
        return $this->container['jti'] ?? '';
    }

    /**
     * 设置token的数据载荷
     * @param array $payload
     * @return $this
     */
    public function setPayload(array $payload): static
    {
        $this->container['payload'] = $payload;
        return $this;
    }

    /**
     * 获取token的数据载荷
     * @return array
     */
    public function getPayload(): array
    {
        return $this->container['payload'] ?? [];
    }

}