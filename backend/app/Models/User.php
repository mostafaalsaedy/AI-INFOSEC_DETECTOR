<?php

namespace App\Models;

use Database\Factories\UserFactory;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

/**
 * A dashboard operator.
 *
 * Roles are deliberately coarse - viewer, analyst, admin - because the
 * sensitivity of the data means access decisions should be easy to audit.
 */
class User extends Authenticatable
{
    /** @use HasFactory<UserFactory> */
    use HasApiTokens, HasFactory, Notifiable;

    public const ROLE_VIEWER = 'viewer';

    public const ROLE_ANALYST = 'analyst';

    public const ROLE_ADMIN = 'admin';

    /** All roles, ordered from least to most privileged. */
    public const ROLES = [
        self::ROLE_VIEWER,
        self::ROLE_ANALYST,
        self::ROLE_ADMIN,
    ];

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
        'role',
        'is_active',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var list<string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'last_login_at' => 'datetime',
            'password' => 'hashed',
            'is_active' => 'boolean',
        ];
    }

    /*
    |--------------------------------------------------------------------------
    | Scopes
    |--------------------------------------------------------------------------
    */

    public function scopeActive(Builder $query): Builder
    {
        return $query->where('is_active', true);
    }

    public function scopeWithRole(Builder $query, string $role): Builder
    {
        return $query->where('role', $role);
    }

    /*
    |--------------------------------------------------------------------------
    | Authorisation helpers
    |--------------------------------------------------------------------------
    */

    public function isAdmin(): bool
    {
        return $this->role === self::ROLE_ADMIN;
    }

    public function isAnalyst(): bool
    {
        return in_array($this->role, [self::ROLE_ANALYST, self::ROLE_ADMIN], true);
    }

    /**
     * True when this user's role is at least as privileged as the given one.
     */
    public function hasAtLeastRole(string $role): bool
    {
        $current = array_search($this->role, self::ROLES, true);
        $required = array_search($role, self::ROLES, true);

        return $current !== false && $required !== false && $current >= $required;
    }

    /**
     * Permission map handed to the dashboard after login.
     *
     * @return array<string, bool>
     */
    public function permissions(): array
    {
        return [
            'read_alerts' => true,
            'read_analytics' => true,
            'update_alerts' => $this->isAnalyst(),
            'bulk_update_alerts' => $this->isAnalyst(),
            'export_data' => $this->isAnalyst(),
            'user_analytics' => $this->isAdmin(),
            'export_pii' => $this->isAdmin(),
            'manage_users' => $this->isAdmin(),
            'admin' => $this->isAdmin(),
        ];
    }

    public function recordLogin(): void
    {
        $this->forceFill(['last_login_at' => now()])->save();
    }
}
