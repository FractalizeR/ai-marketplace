<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class AdminController extends AbstractController
{
    #[Route('/admin/dashboard', name: 'admin_dashboard', methods: ['GET'])]
    public function dashboard(): Response
    {
        return new Response('ok');
    }

    #[Route('/profile/edit', name: 'profile_edit', methods: ['POST'])]
    public function editProfile(): Response
    {
        return new Response('ok');
    }
}
