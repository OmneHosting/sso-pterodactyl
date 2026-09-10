<?php

namespace WemX\Sso\Http\Controllers;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Auth;
use Pterodactyl\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class SsoController 
{

    /**
     * Attempt to login the user
     *
     * @return Redirect
     */
    public function handle($token)
    {
        if(!$this->hasToken($token)) {
            return redirect()->back()->withError('Token does not exists or has expired');
        }

        try {
            Auth::loginUsingId($this->getToken($token));
            $this->invalidateToken($token);

            return redirect()->intended('/');
        } catch(\Exception $error) {
            return redirect()->back()->withError('Something went wrong, please try again.');
        }
    }

    /**
     * Handle incoming webhook
     *
     * @return $token
     */
    public function webhook(Request $request)
    {
        if(!config('sso-wemx.secret')) {
            return response(['success' => false, 'message' => 'Please configure a SSO Secret'], 403);
        }

        if(!hash_equals((string) config('sso-wemx.secret'), (string) $request->input('sso_secret'))) {
            return response(['success' => false, 'message' => 'Please provide valid credentials'], 403);
        }

        $user = User::findOrFail($request->input('user_id'));

        if($reason = $this->blockedLoginReason($user)) {
            return response(['success' => false, 'message' => $reason], 501);
        }

        return response(['success' => true, 'redirect' => route('sso-wemx.login', $this->generateToken($request->input('user_id')))], 200);
    }

    /**
     * Pterodactyl's users table stores the TOTP flag as `use_totp` (there is no `2fa`
     * column), so checking that key was always falsy and the 2FA block never fired.
     * Both checks fail closed: a missing `root_admin` or `use_totp` key blocks the
     * login rather than silently allowing it.
     *
     * Accepts the model (or an array in tests) via array access rather than
     * ->toArray(), since toArray() applies Eloquent's $hidden filtering and could
     * drop use_totp, causing every login to fail closed.
     *
     * @param  \Pterodactyl\Models\User|array  $user
     * @return string|null the block reason, or null if the login is allowed
     */
    protected function blockedLoginReason($user): ?string
    {
        if(!isset($user['root_admin']) || $user['root_admin']) {
            return 'You cannot automatically login to admin accounts.';
        }

        if(!isset($user['use_totp'])) {
            return 'Unable to determine 2FA status for this account.';
        }

        if($user['use_totp']) {
            return 'Logging into accounts with 2 Factor Authentication enabled is not supported.';
        }

        return null;
    }

    /**
     * Generate a random access token and store the user_id inside
     * Tokens are only valid for 60 seconds
     *
     * @return mixed
     */
    protected function generateToken($user_id)
    {
        $token = Str::random(config('sso-wemx.token.length', 48));
        Cache::add($token, $user_id, config('sso-wemx.token.lifetime', 60));
        return $token;
    }

    /**
     * Returns the value of the token
     *
     * @return mixed
     */
    protected function getToken($token)
    {
        return Cache::get($token);
    }

    /**
     * Returns true or false based on if the token exists
     *
     * @return bool
     */
    protected function hasToken($token): bool
    {
        return Cache::has($token);
    }

    /**
     * Invalidates the token so it can no longer be used
     *
     * @return void
     */
    protected static function invalidateToken($token)
    {
        Cache::forget($token);
    }
}
