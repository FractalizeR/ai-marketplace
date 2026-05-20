<?php

declare(strict_types=1);

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/admin/users')]
class UserController extends AbstractController
{
    #[Route('', name: 'admin_users_create', methods: ['POST'])]
    #[IsGranted('ROLE_ADMIN')]
    public function create(Request $request): JsonResponse
    {
        return $this->json(['ok' => true]);
    }

    #[Route('/{id}', name: 'admin_users_delete', methods: ['DELETE'])]
    public function delete(int $id): JsonResponse
    {
        $this->denyAccessUnlessGranted('ROLE_SUPERADMIN');
        return $this->json(['ok' => true]);
    }

    #[Route('/{id}', name: 'admin_users_view', methods: ['GET'])]
    public function view(int $id): JsonResponse
    {
        return $this->json(['id' => $id]);
    }
}
