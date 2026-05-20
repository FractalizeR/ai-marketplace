<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Storage;

class PaymentController extends Controller
{
    // VULN: hardcoded_secret — Stripe live key in source.
    private const STRIPE_KEY = 'sk_live_FAKE_FIXTURE_KEY_NOT_REAL';

    public function process(Request $request)
    {
        $this->authorize('process-payment', $request->input('order_id'));

        // VULN: serialization — unserialize on user-controllable data.
        $payload = unserialize($request->input('payload'));

        // VULN: serialization — Crypt::decrypt on cookie.
        $token = Crypt::decrypt($request->cookie('payment_token'));

        // VULN: file_op — file_get_contents on user-supplied path.
        $template = file_get_contents($request->input('template_path'));

        // file_op — Storage facade.
        Storage::put('orders/' . $request->input('id'), $payload);

        // http_client — Laravel Http facade.
        $response = Http::withHeaders(['Authorization' => 'Bearer ' . self::STRIPE_KEY])
            ->post('https://api.stripe.com/v1/charges', [
                'amount' => $request->input('amount'),
            ]);

        // fintech_marker — bcmath operation on monetary value.
        $totalCents = bcmul((string)$request->input('amount'), '100');

        return response()->json(['status' => 'ok']);
    }
}
