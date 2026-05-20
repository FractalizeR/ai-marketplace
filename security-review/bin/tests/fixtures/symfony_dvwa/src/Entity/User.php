<?php

declare(strict_types=1);

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'users')]
class User
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    private ?int $id = null;

    #[ORM\Column(type: 'string', length: 180, unique: true)]
    private string $email = '';

    // VULN: plaintext_password_storage id=DVWA-14
    // No `length` constraint suggesting hashed value (180+ chars expected for bcrypt/argon).
    // Combined with security.yaml hasher=plaintext, every account password is stored
    // as raw user input. setPassword writes the parameter without hashing.
    #[ORM\Column(type: 'string', length: 64)]
    private string $password = '';

    #[ORM\Column(type: 'json')]
    private array $roles = [];

    // VULN: sensitive_field_unmasked id=DVWA-11 (entity anchor)
    // Persistent OAuth token in plaintext — pair with UserCrudController exposing
    // it via TextField without formatValue/onlyOnIndex. Sink_kind family `disclosure`.
    #[ORM\Column(type: 'string', length: 255, nullable: true)]
    private ?string $apiKey = null;

    public function getId(): ?int { return $this->id; }
    public function getEmail(): string { return $this->email; }
    public function setEmail(string $email): void { $this->email = $email; }
    public function getPassword(): string { return $this->password; }

    public function setPassword(string $password): void
    {
        // Direct assignment — no PasswordHasherInterface call. Worker's authz
        // wave should flag this together with the security.yaml setting.
        $this->password = $password;
    }

    public function getRoles(): array { return $this->roles ?: ['ROLE_USER']; }
    public function setRoles(array $roles): void { $this->roles = $roles; }

    public function getApiKey(): ?string { return $this->apiKey; }
    public function setApiKey(?string $apiKey): void { $this->apiKey = $apiKey; }
}
