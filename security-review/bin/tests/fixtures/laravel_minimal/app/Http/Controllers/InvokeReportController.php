<?php

namespace App\Http\Controllers;

class InvokeReportController extends Controller
{
    public function __invoke()
    {
        return view('welcome');
    }
}
