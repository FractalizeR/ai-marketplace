<?php

declare(strict_types=1);

namespace App\Controller;

use App\Repository\PostRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/posts')]
class PostController extends AbstractController
{
    public function __construct(private readonly PostRepository $posts)
    {
    }

    #[Route('/{id}', name: 'post_show', methods: ['GET'], requirements: ['id' => '\\d+'])]
    public function show(int $id): Response
    {
        // The template `post/show.html.twig` renders `{{ post.body|raw }}` with
        // twig.yaml `autoescape: false`. Whatever a privileged author posts is
        // executed in the viewer's browser. See VULN: stored_xss id=DVWA-03 anchor
        // in the template file.
        $post = $this->posts->find($id);
        return $this->render('post/show.html.twig', ['post' => $post]);
    }
}
