<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('security_alerts', function (Blueprint $table) {
            $table->id();

            // Reference to interaction
            $table->foreignId('interaction_id')->nullable()->constrained('ai_interactions')->nullOnDelete();

            // Alert information
            $table->enum('severity', ['low', 'medium', 'high', 'critical'])->index();
            $table->string('alert_type', 100)->index(); // 'sensitive_data', 'policy_violation', etc.
            $table->string('title', 200);
            $table->text('description');

            // Detection details
            $table->json('detection_rules'); // Rules that triggered the alert
            $table->json('evidence')->nullable(); // Evidence data (anonymized)
            $table->integer('confidence_score')->default(0); // 0-100

            // Status tracking
            $table->enum('status', ['open', 'investigating', 'resolved', 'false_positive'])->default('open')->index();
            $table->string('assigned_to')->nullable()->index();
            $table->text('resolution_notes')->nullable();
            $table->timestamp('resolved_at')->nullable();

            // Notification tracking
            $table->boolean('notification_sent')->default(false);
            $table->timestamp('notification_sent_at')->nullable();
            $table->json('notification_channels')->nullable(); // email, slack, etc.

            $table->timestamps();

            // Indexes
            $table->index(['severity', 'status', 'created_at']);
            $table->index(['alert_type', 'created_at']);
            $table->index(['status', 'assigned_to']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('security_alerts');
    }
};
