<?php

declare(strict_types=1);

namespace Hyperf\Auth\Command;

use Hyperf\Command\Annotation\Command;
use Hyperf\Command\Command as HyperfCommand;
use Symfony\Component\Console\Input\InputOption;

#[Command]
class AuthCommand extends HyperfCommand
{
    /**
     * 执行的命令行.
     *
     * @var string
     */
    protected ?string $name = 'auth:publish';

    public function handle(): void
    {
        // 从 $input 获取 config 参数
        $argument = $this->input->getOption('config');
        if ($argument) {
            $this->copySource(__DIR__ . '/../../publish/auth.php', BASE_PATH . '/config/autoload/auth.php');
            $this->line('The hyperf-auth configuration file has been generated', 'info');
        }
    }

    protected function getOptions()
    {
        return [
            ['config', null, InputOption::VALUE_NONE, 'Publish the configuration for hyperf-auth'],
        ];
    }

    /**
     * 复制文件到指定的目录中.
     *
     * @param $copySource
     * @param $toSource
     */
    protected function copySource($copySource, $toSource): void
    {
        copy($copySource, $toSource);
    }
}
