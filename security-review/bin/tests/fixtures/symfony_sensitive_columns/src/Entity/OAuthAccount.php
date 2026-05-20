<?php

declare(strict_types=1);

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class OAuthAccount
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(type: 'encrypted_string')]
    private string $accessToken = '';

    #[ORM\Column(type: 'string')]
    #[Encrypted]
    private string $refreshToken = '';
}
