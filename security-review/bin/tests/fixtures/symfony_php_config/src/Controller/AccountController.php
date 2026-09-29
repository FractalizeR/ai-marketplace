<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class AccountController extends AbstractController
{
    #[Route('/account/settings', name: 'account_settings', methods: ['GET', 'POST'])]
    public function settings(): Response
    {
        return new Response('ok');
    }

    #[Route('/admin/users', name: 'admin_users', methods: ['GET'])]
    public function adminUsers(): Response
    {
        return new Response('ok');
    }
}
