<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class UserSession extends Model
{
    use HasFactory;

    protected $fillable = [
        'session_id',
        'user_id',
        'extension_version',
        'browser',
        'browser_version',
        'os',
        'user_agent',
        'session_started_at',
        'last_activity_at',
        'session_ended_at',
        'total_interactions',
        'total_alerts',
        'platforms_used',
        'duration_minutes',
        'monitoring_enabled',
        'data_collection_consent',
        'consent_updated_at',
    ];

    protected $casts = [
        'platforms_used' => 'array',
        'monitoring_enabled' => 'boolean',
        'data_collection_consent' => 'boolean',
        'session_started_at' => 'datetime',
        'last_activity_at' => 'datetime',
        'session_ended_at' => 'datetime',
        'consent_updated_at' => 'datetime',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    public function aiInteractions(): HasMany
    {
        return $this->hasMany(AiInteraction::class, 'session_id', 'session_id');
    }

    // Scopes
    public function scopeActive($query)
    {
        return $query->whereNull('session_ended_at')
            ->where('last_activity_at', '>=', now()->subHours(4));
    }

    public function scopeWithConsent($query)
    {
        return $query->where('data_collection_consent', true);
    }

    public function scopeByUser($query, $userId)
    {
        return $query->where('user_id', $userId);
    }

    public function scopeMonitoringEnabled($query)
    {
        return $query->where('monitoring_enabled', true);
    }

    public function scopeRecentFirst($query)
    {
        return $query->orderBy('last_activity_at', 'desc');
    }

    public function scopeLongSessions($query, $minMinutes = 60)
    {
        return $query->where('duration_minutes', '>=', $minMinutes);
    }

    // Helper methods
    public function isActive(): bool
    {
        return is_null($this->session_ended_at) &&
               $this->last_activity_at >= now()->subHours(4);
    }

    public function hasConsent(): bool
    {
        return $this->data_collection_consent;
    }

    public function isMonitoringEnabled(): bool
    {
        return $this->monitoring_enabled;
    }

    public function updateActivity(): void
    {
        $this->update([
            'last_activity_at' => now(),
        ]);

        $this->updateDuration();
    }

    public function endSession(): void
    {
        $this->update([
            'session_ended_at' => now(),
        ]);

        $this->updateDuration();
    }

    public function addPlatform(string $platform): void
    {
        $platforms = $this->platforms_used ?? [];

        if (! in_array($platform, $platforms)) {
            $platforms[] = $platform;
            $this->update(['platforms_used' => $platforms]);
        }
    }

    public function incrementInteractions(): void
    {
        $this->increment('total_interactions');
    }

    public function incrementAlerts(): void
    {
        $this->increment('total_alerts');
    }

    private function updateDuration(): void
    {
        $startTime = $this->session_started_at;
        $endTime = $this->session_ended_at ?? $this->last_activity_at ?? now();

        $durationMinutes = $startTime->diffInMinutes($endTime);

        $this->update(['duration_minutes' => $durationMinutes]);
    }

    public function getSessionDurationHumanAttribute(): string
    {
        if ($this->duration_minutes < 60) {
            return $this->duration_minutes.' minutes';
        }

        $hours = floor($this->duration_minutes / 60);
        $minutes = $this->duration_minutes % 60;

        return $hours.'h '.$minutes.'m';
    }

    public function getPlatformCountAttribute(): int
    {
        return count($this->platforms_used ?? []);
    }

    public function getRiskScoreAttribute(): float
    {
        if ($this->total_interactions === 0) {
            return 0;
        }

        return ($this->total_alerts / $this->total_interactions) * 100;
    }

    public function getBrowserInfoAttribute(): string
    {
        $parts = [];

        if ($this->browser) {
            $parts[] = $this->browser;
            if ($this->browser_version) {
                $parts[] = $this->browser_version;
            }
        }

        if ($this->os) {
            $parts[] = "on {$this->os}";
        }

        return implode(' ', $parts) ?: 'Unknown';
    }
}
