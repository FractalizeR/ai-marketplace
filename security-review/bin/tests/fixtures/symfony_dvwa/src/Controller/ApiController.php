<?php

declare(strict_types=1);

namespace App\Controller;

use Doctrine\DBAL\Connection;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/api')]
class ApiController
{
    public function __construct(private readonly Connection $db)
    {
    }

    #[Route('/search', name: 'api_search', methods: ['GET'])]
    public function search(Request $request): Response
    {
        // VULN: native_sql_concat id=DVWA-02
        // Direct DBAL SQL concatenation with the request `q` parameter.
        // Sink_kind=native_sql_concat, root_cause_family=injection.
        $needle = $request->query->get('q', '');
        $sql = "SELECT id, email FROM users WHERE email LIKE '%" . $needle . "%'";
        $rows = $this->db->fetchAllAssociative($sql);
        return new JsonResponse($rows);
    }

    #[Route('/session/restore', name: 'api_session_restore', methods: ['GET'])]
    public function restoreSession(Request $request): Response
    {
        // VULN: untrusted_unserialize id=DVWA-07
        // PHP serialized payload from a cookie — classic gadget chain RCE if the
        // cookie is unsigned/unencrypted. Sink_kind=untrusted_unserialize,
        // root_cause_family=deserialization.
        $payload = $request->cookies->get('app_session', '');
        $state = unserialize(base64_decode($payload));
        return new JsonResponse(['state' => $state]);
    }
}
