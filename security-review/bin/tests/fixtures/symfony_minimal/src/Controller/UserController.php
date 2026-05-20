<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/users')]
class UserController extends AbstractController
{
    #[Route('/me', name: 'user_me', methods: ['GET'])]
    public function me(): JsonResponse
    {
        /** @var User $user */
        $user = $this->getUser();

        return $this->json([
            'id' => $user->getId(),
            'email' => $user->getEmail(),
        ]);
    }

    #[Route('/{id}', name: 'user_profile', methods: ['GET'])]
    public function profile(int $id, UserRepository $repo): JsonResponse
    {
        $user = $repo->find($id);
        if ($user === null) {
            return $this->json(['error' => 'not_found'], Response::HTTP_NOT_FOUND);
        }

        return $this->json([
            'id' => $user->getId(),
            'email' => $user->getEmail(),
        ]);
    }

    #[Route('/{id}', name: 'user_update', methods: ['PUT'])]
    public function update(User $user, Request $request): JsonResponse
    {
        $this->denyAccessUnlessGranted('USER_EDIT', $user);
        $user->setEmail((string) $request->request->get('email', $user->getEmail()));

        return $this->json(['ok' => true]);
    }
}
