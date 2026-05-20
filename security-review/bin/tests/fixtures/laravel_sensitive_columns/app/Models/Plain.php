<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Plain extends Model
{
    protected $fillable = [
        'name',
        'email',
        'description',
    ];
}
