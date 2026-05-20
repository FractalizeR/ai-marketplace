<?php

declare(strict_types=1);

namespace App\Messenger;

use Symfony\Component\Messenger\Attribute\AsMessageHandler;

final class SendEmailMessage
{
    public function __construct(public string $to, public string $subject, public string $body) {}
}

#[AsMessageHandler]
final class SendEmailHandler
{
    public function __invoke(SendEmailMessage $message): void
    {
        // intentionally empty — exercise message handler discovery only
    }
}
