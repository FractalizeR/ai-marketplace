<?php

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return static function (ContainerConfigurator $container): void {
    $container->extension('security', [
        'access_control' => [
            ['path' => '^/admin', 'roles' => ['ROLE_ADMIN']],
            ['path' => '^/account', 'roles' => ['ROLE_USER']],
        ],
    ]);
};
