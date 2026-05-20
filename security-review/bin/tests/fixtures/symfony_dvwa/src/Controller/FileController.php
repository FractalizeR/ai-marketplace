<?php

declare(strict_types=1);

namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/files')]
class FileController
{
    private const STORAGE_ROOT = '/var/app/uploads';

    #[Route('/download', name: 'files_download', methods: ['GET'])]
    public function download(Request $request): Response
    {
        // VULN: path_traversal id=DVWA-05
        // Untrusted `name` from query is concatenated into a filesystem path.
        // `../../etc/passwd` escapes STORAGE_ROOT. Sink_kind=path_traversal,
        // root_cause_family=ssrf-fileops (fs sub-family).
        $name = (string) $request->query->get('name', 'README.txt');
        $bytes = file_get_contents(self::STORAGE_ROOT . '/' . $name);
        if ($bytes === false) {
            return new Response('not found', Response::HTTP_NOT_FOUND);
        }
        return new Response($bytes, 200, ['Content-Type' => 'application/octet-stream']);
    }
}
