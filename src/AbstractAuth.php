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

use Hyperf\Contract\ConfigInterface;
use Psr\Container\ContainerInterface;

abstract class AbstractAuth implements AuthInterface
{
    /**
     * @var string
     */

    public $headerAuthKey = 'Authorization';

    public $tokenPrefix = 'Bearer ';

    public $tokenScenePrefix = 'auth_scene';

    protected $alg = 'HS256';

    /**
     * @var array Supported algorithms
     */
    protected $supportedAlgs = [
        'HS256',
        'HS384',
        'HS512',
        'ES384',
        'ES256',
        'ES256K',
        'RS256',
        'RS384',
        'RS512',
        'EdDSA',
    ];

    protected $symmetryAlgs = [
        'HS256',
        'HS384',
        'HS512',
    ];

    protected $asymmetricAlgs = [
        'ES384',
        'ES256',
        'ES256K',
        'RS256',
        'RS384',
        'RS512',
        'EdDSA',
    ];

    /**
     * 当前 token 生成 token 的场景值
     * @var string
     */
    private $scene = 'default';

    /**
     * @var string
     */
    private $scenePrefix = 'scene';

    /**
     * @var ContainerInterface
     */
    private $container;

    /**
     * @var ConfigInterface
     */
    private $config;

    /**
     * jwt 配置前缀
     * @var string
     */
    private $configPrefix = 'auth';

    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
        $this->config = $this->container->get(ConfigInterface::class);

        // 合并场景配置，并且兼容 2.0.6 以下的配置
        $config = $this->config->get($this->configPrefix);
        if (empty($config['alg'])) {
            $config['alg'] = $this->alg;
        }
        $scenes = $config['scene'];
        unset($config['scene']);
        foreach ($scenes as $key => $scene) {
            $sceneConfig = array_merge($config, $scene);
            $this->setSceneConfig($key, $sceneConfig);
        }
    }

    /**
     * 设置依赖注入容器
     * 
     * 本方法用于注入一个依赖注入容器实例，该容器可用于管理对象之间的依赖关系。
     * 通过设置容器，本类可以在需要时从容器中获取其他依赖对象，从而实现依赖的解耦。
     * 
     * @param ContainerInterface $container 依赖注入容器的接口。通过这个接口，本类可以访问容器中的其他服务。
     * @return $this 返回当前对象实例，支持链式调用。
     */
    public function setContainer(ContainerInterface $container)
    {
        $this->container = $container;
        return $this;
    }

    /**
     * 获取容器实例
     * 
     * 本方法旨在返回当前实例所依赖的容器对象。容器对象作为一个全局管理者，
     * 负责管理所有依赖项的生命周期，提供依赖注入功能，从而解耦应用程序的各个部分。
     * 
     * @return ContainerInterface 返回一个实现了ContainerInterface的容器对象
     */
    public function getContainer()
    {
        // 直接返回存储的容器实例
        return $this->container;
    }

    /**
     * 根据场景获取配置信息。
     * 
     * 本函数旨在通过指定的场景名称，从配置对象中获取相应的配置值。
     * 场景名称默认为'default'，这意味着如果没有指定场景，将返回默认场景的配置。
     * 这种设计允许应用程序根据不同的运行环境或使用场景，灵活地获取相应的配置信息，
     * 从而提高应用程序的适应性和灵活性。
     * 
     * @param string $scene 指定的场景名称。用于从配置中检索特定场景的配置信息。
     *                     如果未指定场景名称，则默认使用'default'场景。
     * @return mixed 返回指定场景的配置信息。配置信息的具体类型取决于配置对象的实现。
     */
    public function getSceneConfig(string $scene = 'default')
    {
        // 通过拼接配置前缀和场景前缀以及指定的场景名称，从配置对象中获取配置值。
        return $this->config->get("{$this->configPrefix}.{$this->scenePrefix}.{$scene}");
    }

    /**
     * 设置特定场景的配置。
     * 
     * 本函数用于在当前配置对象中设置与特定场景相关的配置值。
     * 如果未指定场景，则默认使用'default'场景。此方法支持链式调用。
     * 
     * @param string $scene 场景名称，用于指定配置的适用场景。默认为'default'。
     * @param mixed $value 配置的值，可以是任何类型。如果未指定值，则默认为null。
     * @return $this 返回当前配置对象，支持链式调用。
     */
    public function setSceneConfig(string $scene = 'default', $value = null)
    {
        // 通过拼接配置前缀和场景前缀来构建完整的配置键名，然后设置配置值
        $this->config->set("{$this->configPrefix}.{$this->scenePrefix}.{$scene}", $value);
        return $this;
    }

    /**
     * 获取场景设置
     * 
     * 本方法用于返回当前对象的场景属性值。场景设置可能用于不同情境下的对象行为差异化，
     * 或者用于标识对象当前所处的环境或状态。
     * 
     * @return string 返回当前对象的场景属性值
     */
    public function getScene()
    {
        return $this->scene;
    }

    /**
     * 设置场景名称
     * 
     * 本方法用于设定当前操作的场景名称。场景名称可以用于区分不同的使用情境，
     * 例如在不同的业务逻辑中或者在不同的阶段（如测试阶段和生产阶段）使用不同的场景。
     * 默认情况下，场景名称被设置为'default'，但可以根据需要传入任何字符串来指定特定的场景。
     * 
     * @param string $scene 场景名称，默认为'default'
     * @return $this 返回当前对象实例，支持链式调用
     */
    public function setScene(string $scene = 'default')
    {
        $this->scene = $scene;
        return $this;
    }
}
