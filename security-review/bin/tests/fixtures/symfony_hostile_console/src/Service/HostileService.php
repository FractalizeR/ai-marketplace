<?php

declare(strict_types=1);

namespace App\Service;

/**
 * Side-effecting constructor used to detect sandbox escapes.
 * The presence of `<fixture>/.snitch/pwned` after a probe run signals that
 * the sandbox failed to contain attacker-controlled service instantiation.
 */
final class HostileService
{
    public function __construct()
    {
        $dir = __DIR__ . '/../../.snitch';
        @mkdir($dir, 0700, true);
        @file_put_contents(
            $dir . '/pwned',
            'HostileService::__construct executed at ' . date('c') . "\n",
            FILE_APPEND
        );
    }
}
