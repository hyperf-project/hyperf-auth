<?php

declare(strict_types=1);
/**
 * This file is part of Hyperf-Auth.
 *
 * @link      https://github.com/hyperf-project/hyperf-auth
 * @document  https://github.com/hyperf-project/docs
 * @contact   zxp@sjq.app
 * @
 */

namespace Hyperf\Auth;

use Psr\Container\ContainerInterface;
use Psr\SimpleCache\CacheInterface;
use Hyperf\HttpServer\Contract\RequestInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use UnexpectedValueException;

class Auth extends AbstractAuth
{
    /**
     * @var RequestInterface
     */
    public $request;

    /**
     * @var CacheInterface
     */
    public $cache;

    public function __construct(ContainerInterface $container)
    {
        parent::__construct($container);
        $this->request = $this->getContainer()->get(RequestInterface::class);
        $this->cache = $this->getContainer()->get(CacheInterface::class);        
    }


    public function createToken(array $claims = [], ?array $headers = []): array
    {
        $config = $this->getSceneConfig($this->getScene());
        if (empty($config)) {
            throw new AuthException("The auth scene [{$this->getScene()}] not found", 400);
        }
        $key = $this->getKey($config);
        if (empty($key)) {
            throw new AuthException("The auth key is empty", 400);
        }
        $alg = $config['alg'];
        if (!in_array($alg, $this->supportedAlgs)) {
            throw new AuthException("The auth alg is not supported", 400);
        }
        $idKey = $config['id_key'];
        if (empty($claims[$idKey])) {
            throw new AuthException("There is no {$idKey} key in the claims", 400);
        }
        if ($config['login_type'] != 'single') {
            $uniqid = uniqid($this->getScene() . "_", true);
        } else {
            $uniqid = $this->getScene() . "_" . $claims[$idKey];
        }
        $claims[$this->tokenScenePrefix] = $this->getScene(); // 加入场景值
        $host = $this->request->getUri()->getHost();
        $now = time();
        $expireTime = $now + $config['ttl'] ?? 3600;
        $token = (new Builder())
            // Configures the issuer (iss claim)
            ->issuedBy($host)
            // Configures the audience (aud claim)
            ->permittedFor($host)
            // Configures the subject of the token (sub claim)
            // ->relatedTo('hyperf')
            // Configures the id (jti claim)
            ->identifiedBy($uniqid)
            // Configures the time that the token was issue (iat claim)
            ->issuedAt($now)
            // Configures the time that the token can be used (nbf claim)
            ->canOnlyBeUsedAfter($now)
            // Configures the expiration time of the token (exp claim)
            ->expiresAt($now)
            // Configures new claim with params
            ->withClaims($claims)
            // Configures new header with headers
            ->withHeaders($headers)
            ->getToken($key, $alg);
        $this->cache->set('auth:' . $this->getScene() . ':' . $claims[$idKey] . ':token_'. $uniqid, $token, $expireTime);
        return compact('token', 'expireTime');
    }

    public function parseToken(string $token): array
    {
        $config = $this->getSceneConfig($this->getScene());
        $idKey = $config['id_key'];
        $payload = JWT::decode($token, new Key($this->getKey($config, 'public'), $this->alg));
        if (!empty($payload)) {
            $tokenInfo = json_decode(json_encode($payload), true, 512, JSON_THROW_ON_ERROR);

            if (explode("_", $tokenInfo['jti'])[1] != $this->getScene()) {
                return [];
            }
            $cacheToken = $this->cache->get('auth:' . $this->getScene() . ':' . $tokenInfo[$idKey] . ':token_' . $tokenInfo['jti']);
            if (!empty($tokenInfo) && $token !== $cacheToken) {
                return [];
            }
            return $tokenInfo;
        } else {
            return [];
        }
    }

    public function verifyToken(?string $token = null): bool
    {
        $config = $this->getSceneConfig($this->getScene());

        try {
            $token = $token ?? $this->getHeaderToken();
            JWT::decode($token, new Key($this->getKey($config, 'public'), $this->alg));
            return true;
        } catch (UnexpectedValueException $e) {
            throw new AuthException($e->getMessage(), 400);
            return false;
        }
    }

    public function refreshToken($token): array
    {
        $tokenInfo = $this->parseToken($token);
        if (!empty($tokenInfo)) {
            foreach ($tokenInfo as $key => $value) {
                if (in_array($tokenInfo[$key], Claims::ALL)) {
                    unset($tokenInfo[$key]);
                }
            }
        }
        return $this->createToken($tokenInfo);
    }

    public function clearToken(string $token): bool
    {
        $config = $this->getSceneConfig($this->getScene());
        $idKey = $config['id_key'];
        $tokenInfo = $this->parseToken($token);
        if (empty($tokenInfo)) {
            return true;
        }
        return $this->cache->delete('auth:' . $this->getScene() . ':' . $tokenInfo[$idKey] . ':token_' . $tokenInfo['jti']);
    }

    /**
     * 从请求头中获取认证 token。
     * 这个方法用于提取请求头中特定字段的值，该字段用于身份验证。
     * 如果 token 不存在或格式不正确，将抛出一个异常。
     *
     * @throws AuthException 如果 token 不存在或无效，抛出认证异常。
     * @return string 获取到的 token 值。
     */
    private function getHeaderToken(): string
    {
        $token = $this->request->getHeaderLine($this->headerAuthKey) ?? '';
        if (strlen($token) > 0) {
            $token = ucfirst($token);
            $tokenArray = explode($this->tokenPrefix, $token);
            $token = trim($tokenArray[1]) ?? $token;
            if (strlen($token) > 0) {
                return $token;
            } 
        }
        throw new AuthException('Token is required', 400);
    }


    /**
     * 获取缓存时间.
     * @return mixed
     */
    public function getTTL(?string $scene = null)
    {
        return $this->getSceneConfig($scene ?? $this->getScene())['ttl'];
    }

    /**
     * 获取对应算法需要的key.
     * @param string $type 配置keys里面的键，获取私钥或者公钥。private-私钥，public-公钥
     * @return null|string
     */
    private function getKey(array $config, string $type = 'private')
    {
        $key = null;
        // 对称算法
        if (in_array($config['alg'], $this->symmetryAlgs)) {
            $key = $config['key'];
        }

        // 非对称
        if (in_array($config['alg'], $this->asymmetricAlgs)) {
            $key = $config['keys'][$type];
        }
        return $key;
    }
}
