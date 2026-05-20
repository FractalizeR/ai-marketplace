<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
use App\Form\UserType;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/auth')]
class AuthController extends AbstractController
{
    public function __construct(private readonly EntityManagerInterface $em)
    {
    }

    #[Route('/login-success', name: 'auth_login_success', methods: ['GET'])]
    public function loginSuccess(Request $request): Response
    {
        // VULN: open_redirect id=DVWA-06
        // `next` parameter is forwarded to RedirectResponse without host validation.
        // `?next=//evil.example` performs an off-host redirect after credential
        // exchange. Sink_kind=open_redirect, root_cause_family=auth.
        $target = (string) $request->query->get('next', '/');
        return new RedirectResponse($target);
    }

    #[Route('/profile', name: 'auth_profile', methods: ['POST'])]
    public function updateProfile(Request $request): Response
    {
        // VULN: missing_csrf id=DVWA-08
        // Mutating POST endpoint backed by a Form whose `csrf_protection` is
        // explicitly disabled (see `UserType::configureOptions()`). Combined
        // with the fact that this is an `_method=POST` outside an authenticator,
        // any cross-origin form submission with the victim's session cookies
        // will mutate user data. Sink_kind=missing_csrf, root_cause_family=auth.
        $user = $this->getUser();
        if (!$user instanceof User) {
            return new Response('unauthenticated', Response::HTTP_FORBIDDEN);
        }
        $form = $this->createForm(UserType::class, $user);
        $form->handleRequest($request);
        if ($form->isSubmitted() && $form->isValid()) {
            $this->em->flush();
            return new RedirectResponse('/auth/profile');
        }
        return new Response('rendered form (omitted)');
    }
}
