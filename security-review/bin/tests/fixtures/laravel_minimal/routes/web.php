<?php

use App\Http\Controllers\HomeController;
use App\Http\Controllers\PostController;
use Illuminate\Support\Facades\Route;

Route::get('/', [HomeController::class, 'index'])->name('home');
Route::get('/posts/{id}', [PostController::class, 'show'])->name('posts.show');
Route::post('/posts/{id}', [PostController::class, 'update'])->middleware('auth');
Route::get('/legacy', 'App\Http\Controllers\HomeController@legacy');
Route::get('/closure', function () {
    return view('welcome');
});
