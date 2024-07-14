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

interface AuthInterface
{
    public function getSceneConfig(string $scene = 'default');

    public function setSceneConfig(string $scene = 'default', $value = null);

    public function getScene();

    public function setScene(string $scene = 'default');
}