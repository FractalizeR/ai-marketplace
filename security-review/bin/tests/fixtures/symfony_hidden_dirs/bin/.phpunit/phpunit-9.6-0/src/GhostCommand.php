<?php

declare(strict_types=1);

namespace PHPUnitBridge;

use Symfony\Component\Console\Command\Command;

// Regression fixture for P8: a phpunit-bridge PHPUnit copy under bin/.phpunit/
// — a real incident source of ~5k extra files that timed out the extractor
// before it reached src/. Must never be parsed (hidden-directory prune).
class GhostCommand extends Command
{
}
