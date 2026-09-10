<?php

namespace WemX\Sso\Tests;

use PHPUnit\Framework\TestCase;
use WemX\Sso\Http\Controllers\SsoController;

class SsoControllerTest extends TestCase
{
    private function blockedLoginReason(array $user): ?string
    {
        $controller = new SsoController();
        $method = new \ReflectionMethod(SsoController::class, 'blockedLoginReason');
        $method->setAccessible(true);

        return $method->invoke($controller, $user);
    }

    public function test_root_admin_is_blocked(): void
    {
        $reason = $this->blockedLoginReason(['root_admin' => true, 'use_totp' => false]);

        $this->assertNotNull($reason);
    }

    public function test_totp_enabled_user_is_blocked(): void
    {
        $reason = $this->blockedLoginReason(['root_admin' => false, 'use_totp' => true]);

        $this->assertNotNull($reason);
    }

    public function test_missing_totp_key_fails_closed(): void
    {
        $reason = $this->blockedLoginReason(['root_admin' => false]);

        $this->assertNotNull($reason);
    }

    public function test_missing_root_admin_key_fails_closed(): void
    {
        $reason = $this->blockedLoginReason(['use_totp' => false]);

        $this->assertNotNull($reason);
    }

    public function test_regular_user_without_totp_is_allowed(): void
    {
        $reason = $this->blockedLoginReason(['root_admin' => false, 'use_totp' => false]);

        $this->assertNull($reason);
    }
}
