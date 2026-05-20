<?php

declare(strict_types=1);

namespace App\Controller;

use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/users')]
class UserController extends AbstractController
{
    public function __construct(private readonly UserRepository $users)
    {
    }

    #[Route('/{id}', name: 'user_profile', methods: ['GET'], requirements: ['id' => '\\d+'])]
    public function profile(int $id): Response
    {
        // VULN: idor_lookup id=DVWA-13
        // Direct repository find by user-controlled `id` with no `#[IsGranted]`
        // attribute on the action and no `denyAccessUnlessGranted` call inside
        // the body. Combined with the missing-authz access_control rule that
        // gates `^/users` to PUBLIC_ACCESS implicitly (firewall main is stateless
        // → IS_AUTHENTICATED_ANONYMOUSLY), every other user's profile is reachable.
        // Sink_kind=idor_lookup, root_cause_family=authz.
        $user = $this->users->find($id);
        if ($user === null) {
            return new JsonResponse(['error' => 'not found'], Response::HTTP_NOT_FOUND);
        }
        return new JsonResponse([
            'id'      => $user->getId(),
            'email'   => $user->getEmail(),
            'apiKey'  => $user->getApiKey(),  // doubles as DVWA-11 disclosure pivot
        ]);
    }
}
