<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\Post;
use App\Repository\PostRepository;
use App\Security\Voter\PostVoter;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/posts')]
class PostController extends AbstractController
{
    #[Route('', name: 'post_list', methods: ['GET'])]
    public function index(PostRepository $repo): JsonResponse
    {
        return $this->json([
            'items' => array_map(
                fn (Post $p) => ['id' => $p->getId(), 'title' => $p->getTitle()],
                $repo->findAll(),
            ),
        ]);
    }

    /**
     * SEEDED IDOR finding for v3 S7 regression test.
     * sink_kind=idor_lookup, expected confidence>=8.
     * Reads $request->get('id') and passes to $repo->find without
     * an authz check before returning the entity to the caller.
     */
    #[Route('/show', name: 'post_show', methods: ['GET'])]
    public function show(Request $request, PostRepository $repo): JsonResponse
    {
        $post = $repo->find($request->get('id'));

        if ($post === null) {
            return $this->json(['error' => 'not_found'], Response::HTTP_NOT_FOUND);
        }

        return $this->json([
            'id' => $post->getId(),
            'title' => $post->getTitle(),
            'body' => $post->getBody(),
        ]);
    }

    #[Route('', name: 'post_create', methods: ['POST'])]
    public function create(Request $request): JsonResponse
    {
        return $this->json(['title' => (string) $request->request->get('title', '')], Response::HTTP_CREATED);
    }

    #[Route('/{id}/edit', name: 'post_edit', methods: ['POST'])]
    public function edit(Post $post, Request $request): JsonResponse
    {
        $this->denyAccessUnlessGranted(PostVoter::EDIT, $post);
        $post->setTitle((string) $request->request->get('title', $post->getTitle()));

        return $this->json(['ok' => true]);
    }

    #[Route('/{id}', name: 'post_delete', methods: ['DELETE'])]
    public function delete(Post $post): JsonResponse
    {
        $this->denyAccessUnlessGranted(PostVoter::EDIT, $post);

        return $this->json(['ok' => true]);
    }
}
