<?php

use App\Http\Controllers\PublicController;
use App\Http\Controllers\UserController;
use Illuminate\Support\Facades\Route;

// Simple auth-protected route via group form. (Laravel canonical form for
// applying middleware to a single route.)
Route::middleware('auth')->group(function () {
    Route::get('/dashboard', [UserController::class, 'dashboard'])->name('dashboard');
});

// Group with multiple middleware — inheritance + chained middleware on inner route.
Route::middleware(['auth', 'admin'])->group(function () {
    Route::post('/api/users', [UserController::class, 'store'])->middleware('throttle:60,1');
});

// Wholly public route — no middleware.
Route::get('/public', [PublicController::class, 'index']);

// Route taking a FormRequest type-hinted parameter — used to detect form_request_authorize.
Route::post('/users', [UserController::class, 'create']);
