<?php

declare(strict_types=1);

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'posts')]
class Post
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    private ?int $id = null;

    #[ORM\Column(type: 'string', length: 255)]
    private string $title = '';

    // Body is rendered as `{{ post.body|raw }}` in show.html.twig — together
    // with twig.yaml `autoescape: false` this is a stored XSS chain.
    #[ORM\Column(type: 'text')]
    private string $body = '';

    #[ORM\ManyToOne(targetEntity: User::class)]
    #[ORM\JoinColumn(nullable: false)]
    private User $author;

    public function getId(): ?int { return $this->id; }
    public function getTitle(): string { return $this->title; }
    public function setTitle(string $title): void { $this->title = $title; }
    public function getBody(): string { return $this->body; }
    public function setBody(string $body): void { $this->body = $body; }
    public function getAuthor(): User { return $this->author; }
    public function setAuthor(User $u): void { $this->author = $u; }
}
