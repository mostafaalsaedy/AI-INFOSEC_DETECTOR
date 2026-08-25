<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Sanctum\Sanctum;
use Tests\TestCase;

/**
 * Covers the routing and authentication boundary: which endpoints are public,
 * which require a token, and which require an administrator.
 */
class ApiRoutingTest extends TestCase
{
    use RefreshDatabase;

    public function test_health_endpoint_is_public(): void
    {
        $this->getJson('/api/v1/health')
            ->assertOk()
            ->assertJsonStructure(['status', 'timestamp', 'version'])
            ->assertJson(['status' => 'healthy']);
    }

    public function test_dashboard_requires_authentication(): void
    {
        $this->getJson('/api/v1/dashboard/overview')
            ->assertUnauthorized()
            ->assertJson(['error' => 'Unauthenticated']);
    }

    public function test_unauthenticated_api_requests_get_json_not_a_redirect(): void
    {
        // Without an Accept header Laravel would otherwise try to redirect to a
        // `login` route, which does not exist in an API-only application.
        $this->get('/api/v1/dashboard/overview')
            ->assertUnauthorized()
            ->assertHeader('content-type', 'application/json');
    }

    public function test_authenticated_user_can_read_the_overview(): void
    {
        Sanctum::actingAs(User::factory()->create(['role' => User::ROLE_ANALYST]));

        $this->getJson('/api/v1/dashboard/overview')
            ->assertOk()
            ->assertJsonStructure([
                'kpis' => [
                    'interactions_last_24h',
                    'open_alerts',
                    'critical_open_alerts',
                    'active_sessions',
                ],
                'recent_alerts',
                'generated_at',
            ]);
    }

    public function test_admin_routes_reject_a_non_admin(): void
    {
        Sanctum::actingAs(User::factory()->create(['role' => User::ROLE_ANALYST]));

        $this->getJson('/api/v1/admin/users')->assertForbidden();
    }

    public function test_admin_routes_accept_an_admin(): void
    {
        Sanctum::actingAs(User::factory()->create(['role' => User::ROLE_ADMIN]));

        $this->getJson('/api/v1/admin/config')
            ->assertOk()
            ->assertJsonStructure(['version', 'data_retention_days', 'risk_thresholds']);
    }

    public function test_collection_endpoint_rejects_an_unsigned_request(): void
    {
        $this->postJson('/api/v1/collect', ['sessionId' => 'test'])
            ->assertUnauthorized();
    }

    public function test_unknown_api_route_returns_404_json(): void
    {
        $this->getJson('/api/v1/does-not-exist')->assertNotFound();
    }
}
