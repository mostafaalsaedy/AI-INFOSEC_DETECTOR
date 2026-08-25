<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('ai_interactions', function (Blueprint $table) {
            $table->id();

            // Session and user tracking
            $table->string('session_id')->index();
            $table->string('user_id')->nullable()->index();

            // Platform information
            $table->string('platform', 50)->index(); // ChatGPT, Claude, etc.
            $table->string('url', 500);
            $table->string('page_title', 200)->nullable();

            // Interaction data
            $table->enum('type', ['prompt', 'response'])->index();
            $table->text('content_hash'); // SHA-256 hash of content
            $table->integer('content_length')->default(0);

            // Risk analysis
            $table->enum('risk_level', ['low', 'medium', 'high'])->default('low')->index();
            $table->integer('risk_score')->default(0)->index();
            $table->json('risk_flags')->nullable(); // Array of detected risk indicators

            // Metadata
            $table->json('metadata')->nullable(); // Additional tracking data
            $table->string('user_agent', 500)->nullable();
            $table->ipAddress('ip_address')->nullable();

            // Privacy and compliance
            $table->boolean('user_consent')->default(false)->index();
            $table->timestamp('consent_date')->nullable();
            $table->boolean('data_processed')->default(false)->index();

            $table->timestamps();
            $table->softDeletes(); // For GDPR compliance

            // Indexes for performance
            $table->index(['platform', 'created_at']);
            $table->index(['risk_level', 'created_at']);
            $table->index(['session_id', 'created_at']);
            $table->index(['user_id', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('ai_interactions');
    }
};
