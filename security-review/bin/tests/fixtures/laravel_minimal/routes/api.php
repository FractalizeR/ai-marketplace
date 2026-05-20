<?php

use App\Http\Controllers\InvokeReportController;
use App\Http\Controllers\UserController;
use Illuminate\Support\Facades\Route;

Route::middleware(['auth:sanctum'])->group(function () {
    Route::get('/users', [UserController::class, 'index']);
    Route::patch('/users/{id}', [UserController::class, 'update']);
    Route::resource('posts', \App\Http\Controllers\PostController::class);
    Route::get('/report', InvokeReportController::class);
    Route::match(['get', 'post'], '/sync', [UserController::class, 'sync']);
});
