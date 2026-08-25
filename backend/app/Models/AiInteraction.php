<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;

class AiInteraction extends Model
{
    use HasFactory, SoftDeletes;

    protected $fillable = [
        'session_id',
        'user_id',
        'platform',
        'url',
        'page_title',
        'type',
        'content_hash',
        'content_length',
        'risk_level',
        'risk_score',
        'risk_flags',
        'metadata',
        'user_agent',
        'ip_address',
        'user_consent',
        'consent_date',
        'data_processed',
    ];

    protected $casts = [
        'risk_flags' => 'array',
        'metadata' => 'array',
        'user_consent' => 'boolean',
        'data_processed' => 'boolean',
        'consent_date' => 'datetime',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
        'deleted_at' => 'datetime',
    ];

    public function session(): BelongsTo
    {
        return $this->belongsTo(UserSession::class, 'session_id', 'session_id');
    }

    public function securityAlerts(): HasMany
    {
        return $this->hasMany(SecurityAlert::class, 'interaction_id');
    }

    // Scopes for filtering
    public function scopeHighRisk($query)
    {
        return $query->where('risk_level', 'high');
    }

    public function scopePlatform($query, $platform)
    {
        return $query->where('platform', $platform);
    }

    public function scopeByUser($query, $userId)
    {
        return $query->where('user_id', $userId);
    }

    public function scopeBySession($query, $sessionId)
    {
        return $query->where('session_id', $sessionId);
    }

    public function scopeWithConsent($query)
    {
        return $query->where('user_consent', true);
    }

    public function scopeRecentFirst($query)
    {
        return $query->orderBy('created_at', 'desc');
    }

    // Helper methods
    public function isHighRisk(): bool
    {
        return $this->risk_level === 'high' || $this->risk_score >= 70;
    }

    public function hasRiskFlag($flag): bool
    {
        return in_array($flag, $this->risk_flags ?? []);
    }

    public function getRiskFlagsCountAttribute(): int
    {
        return count($this->risk_flags ?? []);
    }

    public function getPlatformDisplayNameAttribute(): string
    {
        $platformNames = [
            'ChatGPT' => 'ChatGPT (OpenAI)',
            'Claude' => 'Claude (Anthropic)',
            'DeepSeek' => 'DeepSeek',
            'Perplexity' => 'Perplexity AI',
            'Cohere' => 'Cohere',
            'Replicate' => 'Replicate',
            'HuggingFace' => 'Hugging Face',
            'Together' => 'Together AI',
            'Mistral' => 'Mistral AI',
        ];

        return $platformNames[$this->platform] ?? $this->platform;
    }
}
