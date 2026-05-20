<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use App\Database;
use App\Repository\PostRepository;
use App\Repository\UserRepository;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Factory\AppFactory;

$app = AppFactory::create();

$pdo = Database::connect();
$posts = new PostRepository($pdo);
$users = new UserRepository($pdo);

$app->get('/posts/{id}', function (ServerRequestInterface $req, ResponseInterface $res, array $args) use ($posts) {
    $post = $posts->find((int) $args['id']);
    $res->getBody()->write(json_encode($post));
    return $res->withHeader('Content-Type', 'application/json');
});

$app->get('/users/{id}', function (ServerRequestInterface $req, ResponseInterface $res, array $args) use ($users) {
    $user = $users->find((int) $args['id']);
    $res->getBody()->write(json_encode($user));
    return $res->withHeader('Content-Type', 'application/json');
});

$app->run();
