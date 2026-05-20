<?php

namespace App\Repositories;

use App\Models\Post;

class PostRepository
{
    public function findRecent(int $limit = 10)
    {
        return Post::orderByDesc('created_at')->limit($limit)->get();
    }

    public function findByAuthor(int $userId)
    {
        return Post::where('user_id', $userId)->get();
    }
}
