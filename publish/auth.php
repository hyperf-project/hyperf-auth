<?php
declare(strict_types=1);

return [
    'key' => env('JWT_KEY', 'hyperf689$%^&*'), // 非对称加密使用字符串，请使用自己加密的字符串
    'login_type' => env('JWT_LOGIN_TYPE', 'single'), // 登录方式，single 为单点登录，multi 为多点登录
    'id_key' => 'uid', // 单点登录自定义数据中必须存在 uid 的键值，这个 key 你可以自行定义，只要自定义数据中存在该键即可
    'ttl' => env('JWT_TTL', 7200), // token 过期时间，单位为：秒

    'alg' => env('JWT_ALG', 'HS256'), // jwt 的 hearder 加密算法

    /**
     * JWT 权限 keys
     * 对称算法: HS256, HS384 & HS512 使用 `JWT_KEY`.
     * 非对称算法: RS256, RS384 & RS512 / ES256, ES384 & ES512 使用下面的公钥私钥.
     */
    'keys' => [
        'public' => @file_get_contents(env('JWT_PUBLIC_KEY', '')) ?: '', // 公钥，例如：'file:///path/to/public/key'
        'private' => @file_get_contents(env('JWT_PRIVATE_KEY', '')) ?: '', // 私钥，例如：'file:///path/to/private/key'
    ],

    /**
     * 区分不同场景的 token，比如你一个项目可能会有多种类型的应用接口鉴权,下面自行定义，我只是举例子
     * 下面的配置会自动覆盖根配置，比如 application1 会里面的数据会覆盖掉根数据
     * 下面的 scene 会和根数据合并
     * scene 必须存在一个 default
     * 什么叫根数据，这个配置的一维数组，除了 scene 都叫根配置
     */
    'scene' => [
        'default' => [],
        'application1' => [
            'key' => 'application1', // 非对称加密使用字符串,请使用自己加密的字符串
            'login_type' => 'single', // 登录方式，single 为单点登录，multi 为多点登录
            'id_key' => 'uid',
            'ttl' => 7200, // token 过期时间，单位为：秒
        ],
        'application2' => [
            'key' => 'application2', // 非对称加密使用字符串,请使用自己加密的字符串
            'login_type' => 'single', // 登录方式，single 为单点登录，multi 为多点登录
            'id_key' => 'uid',
            'ttl' => 7200, // token 过期时间，单位为：秒
        ],
        'application3' => [
            'key' => 'application3', // 非对称加密使用字符串,请使用自己加密的字符串
            'login_type' => 'multi', // 登录方式，single 为单点登录，multi 为多点登录
            'ttl' => 7200, // token 过期时间，单位为：秒
        ]
    ],
];