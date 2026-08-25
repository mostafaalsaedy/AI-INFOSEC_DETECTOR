<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('user_sessions', function (Blueprint $table) {
            $table->id();

            // Session identification
            $table->string('session_id')->unique()->index();
            $table->string('user_id')->nullable()->index();
            $table->string('extension_version', 20)->nullable();

            // Browser information
            $table->string('browser', 50)->nullable();
            $table->string('browser_version', 20)->nullable();
            $table->string('os', 50)->nullable();
            $table->string('user_agent', 500)->nullable();

            // Session tracking
            $table->timestamp('session_started_at');
            $table->timestamp('last_activity_at')->nullable();
            $table->timestamp('session_ended_at')->nullable();
            $table->integer('total_interactions')->default(0);
            $table->integer('total_alerts')->default(0);

            // Platform usage
            $table->json('platforms_used')->nullable(); // Array of platforms accessed
            $table->integer('duration_minutes')->default(0);

            // Privacy settings
            $table->boolean('monitoring_enabled')->default(true);
            $table->boolean('data_collection_consent')->default(false);
            $table->timestamp('consent_updated_at')->nullable();

            $table->timestamps();

            // Indexes
            $table->index(['user_id', 'session_started_at']);
            $table->index(['last_activity_at']);
            $table->index(['monitoring_enabled']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('user_sessions');
    }
};
