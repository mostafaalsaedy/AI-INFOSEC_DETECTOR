<?php

namespace Tests\Unit;

use App\Services\RiskAnalysisService;
use Tests\TestCase;

/**
 * Covers the pattern-matching risk engine.
 *
 * The assertions deliberately use fake credentials in well-known test formats
 * so the tests are meaningful without embedding a real secret.
 */
class RiskAnalysisServiceTest extends TestCase
{
    private RiskAnalysisService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new RiskAnalysisService;
    }

    public function test_clean_content_scores_low(): void
    {
        $result = $this->service->analyzeContent(
            'Please summarise the attached quarterly report in three bullet points.'
        );

        $this->assertSame('low', $result['riskLevel']);
        $this->assertEmpty($result['flags']);
    }

    public function test_credit_card_number_is_detected(): void
    {
        // A Visa test number, not a live card.
        $result = $this->service->analyzeContent('My card is 4111 1111 1111 1111');

        $this->assertContains('credit_card', $result['flags']);
        $this->assertGreaterThan(0, $result['score']);
    }

    public function test_social_security_number_is_detected(): void
    {
        $result = $this->service->analyzeContent('SSN 123-45-6789 for the form');

        $this->assertContains('ssn', $result['flags']);
    }

    public function test_api_key_assignment_is_detected(): void
    {
        $result = $this->service->analyzeContent(
            'api_key = abcdefghijklmnopqrstuvwxyz123456'
        );

        $this->assertContains('api_key', $result['flags']);
    }

    public function test_password_assignment_is_detected(): void
    {
        $result = $this->service->analyzeContent('password: hunter2placeholder');

        $this->assertContains('password', $result['flags']);
    }

    public function test_confidentiality_markers_are_detected(): void
    {
        $result = $this->service->analyzeContent(
            'This document is confidential and proprietary.'
        );

        $this->assertContains('confidential', $result['flags']);
    }

    public function test_multiple_matches_raise_the_score(): void
    {
        $single = $this->service->analyzeContent('SSN 123-45-6789');
        $multiple = $this->service->analyzeContent(
            'SSN 123-45-6789 and card 4111 1111 1111 1111 and password: secret123'
        );

        $this->assertGreaterThan($single['score'], $multiple['score']);
    }

    public function test_risk_level_escalates_with_score(): void
    {
        $levels = ['low', 'medium', 'high', 'critical'];

        $clean = $this->service->analyzeContent('Hello, how are you today?');
        $severe = $this->service->analyzeContent(
            'SSN 123-45-6789, card 4111 1111 1111 1111, '
            .'api_key = abcdefghijklmnopqrstuvwxyz123456, password: secret123, '
            .'this is confidential and proprietary'
        );

        $this->assertGreaterThanOrEqual(
            array_search($clean['riskLevel'], $levels, true),
            array_search($severe['riskLevel'], $levels, true)
        );
    }

    public function test_empty_content_is_handled(): void
    {
        $result = $this->service->analyzeContent('');

        $this->assertSame('low', $result['riskLevel']);
        $this->assertSame(0, $result['score']);
    }

    public function test_pattern_stats_describe_the_ruleset(): void
    {
        $stats = $this->service->getPatternStats();

        $this->assertNotEmpty($stats);
    }

    public function test_bulk_analysis_returns_one_result_per_item(): void
    {
        $results = $this->service->analyzeBulk([
            ['content' => 'Nothing sensitive here'],
            ['content' => 'SSN 123-45-6789'],
        ]);

        $this->assertCount(2, $results);
    }
}
