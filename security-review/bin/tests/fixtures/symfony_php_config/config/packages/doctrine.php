<?php

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

// Synthetic hardcoded credential: must reach CONTEXT.md only masked.
return static function (ContainerConfigurator $container): void {
    $container->extension('doctrine', ['dbal' => ['password' => 'Pr0dDbPassw0rd-synthetic']]);
};
