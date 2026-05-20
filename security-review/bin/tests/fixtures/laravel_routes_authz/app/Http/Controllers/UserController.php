<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreUserRequest;
use Illuminate\Http\Request;

class UserController extends Controller
{
    public function __construct()
    {
        $this->middleware('verified')->only(['dashboard']);
    }

    public function dashboard()
    {
        $this->authorize('view-dashboard');
        return view('dashboard');
    }

    public function store(Request $request)
    {
        return ['ok' => true];
    }

    public function me(Request $request)
    {
        return $request->user();
    }

    public function create(StoreUserRequest $request)
    {
        return ['created' => true];
    }
}
