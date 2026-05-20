<?php

declare(strict_types=1);

namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Twig\Environment;

#[Route('/search')]
class SearchController
{
    public function __construct(private readonly Environment $twig)
    {
    }

    #[Route('/render', name: 'search_render', methods: ['GET'])]
    public function render(Request $request): Response
    {
        // VULN: ssti id=DVWA-04
        // User-controlled template source compiled at request time. Twig SSTI =
        // arbitrary PHP via `{{ ['cat /etc/passwd']|map('system')|join }}` etc.
        // Sink_kind=ssti, root_cause_family=injection.
        $tplSource = (string) $request->query->get('tpl', 'hello {{ name }}');
        $template = $this->twig->createTemplate($tplSource);
        return new Response($template->render(['name' => 'world']));
    }
}
