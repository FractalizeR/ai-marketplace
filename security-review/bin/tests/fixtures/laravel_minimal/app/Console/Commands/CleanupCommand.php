<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;

class CleanupCommand extends Command
{
    protected $signature = 'app:cleanup {--dry-run}';

    protected $description = 'Clean up stale records';

    public function handle(): int
    {
        return self::SUCCESS;
    }
}
