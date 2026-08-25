<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class SecurityAlert extends Model
{
    use HasFactory;

    protected $fillable = [
        'interaction_id',
        'severity',
        'alert_type',
        'title',
        'description',
        'detection_rules',
        'evidence',
        'confidence_score',
        'status',
        'assigned_to',
        'resolution_notes',
        'resolved_at',
        'notification_sent',
        'notification_sent_at',
        'notification_channels',
    ];

    protected $casts = [
        'detection_rules' => 'array',
        'evidence' => 'array',
        'notification_sent' => 'boolean',
        'notification_channels' => 'array',
        'resolved_at' => 'datetime',
        'notification_sent_at' => 'datetime',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    public function interaction(): BelongsTo
    {
        return $this->belongsTo(AiInteraction::class, 'interaction_id');
    }

    // Scopes
    public function scopeOpen($query)
    {
        return $query->where('status', 'open');
    }

    public function scopeCritical($query)
    {
        return $query->where('severity', 'critical');
    }

    public function scopeHigh($query)
    {
        return $query->where('severity', 'high');
    }

    public function scopeUnassigned($query)
    {
        return $query->whereNull('assigned_to');
    }

    public function scopeAssignedTo($query, $assignee)
    {
        return $query->where('assigned_to', $assignee);
    }

    public function scopeByType($query, $type)
    {
        return $query->where('alert_type', $type);
    }

    public function scopeRecentFirst($query)
    {
        return $query->orderBy('created_at', 'desc');
    }

    public function scopeHighConfidence($query)
    {
        return $query->where('confidence_score', '>=', 80);
    }

    // Helper methods
    public function isCritical(): bool
    {
        return $this->severity === 'critical';
    }

    public function isHigh(): bool
    {
        return $this->severity === 'high';
    }

    public function isOpen(): bool
    {
        return $this->status === 'open';
    }

    public function isResolved(): bool
    {
        return $this->status === 'resolved';
    }

    public function isAssigned(): bool
    {
        return ! empty($this->assigned_to);
    }

    public function resolve(?string $notes = null, ?string $resolver = null): void
    {
        $this->update([
            'status' => 'resolved',
            'resolution_notes' => $notes,
            'resolved_at' => now(),
            'assigned_to' => $resolver ?? $this->assigned_to,
        ]);
    }

    public function assign(string $assignee): void
    {
        $this->update([
            'assigned_to' => $assignee,
        ]);
    }

    public function markAsFalsePositive(?string $notes = null): void
    {
        $this->update([
            'status' => 'false_positive',
            'resolution_notes' => $notes,
            'resolved_at' => now(),
        ]);
    }

    public function getSeverityColorAttribute(): string
    {
        return match ($this->severity) {
            'critical' => '#dc2626', // red-600
            'high' => '#ea580c',     // orange-600
            'medium' => '#d97706',   // amber-600
            'low' => '#65a30d',      // lime-600
            default => '#6b7280',    // gray-500
        };
    }

    public function getStatusColorAttribute(): string
    {
        return match ($this->status) {
            'open' => '#dc2626',           // red-600
            'investigating' => '#d97706',   // amber-600
            'resolved' => '#16a34a',       // green-600
            'false_positive' => '#6b7280', // gray-500
            default => '#6b7280',          // gray-500
        };
    }

    public function getConfidenceLevelAttribute(): string
    {
        return match (true) {
            $this->confidence_score >= 90 => 'Very High',
            $this->confidence_score >= 80 => 'High',
            $this->confidence_score >= 60 => 'Medium',
            $this->confidence_score >= 40 => 'Low',
            default => 'Very Low',
        };
    }
}
