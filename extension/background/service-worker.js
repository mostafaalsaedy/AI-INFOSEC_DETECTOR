// InfoSec AI Monitor - Background Service Worker

import { buildSignedHeaders } from './request-signing.js';

class SecurityMonitor {
  constructor() {
    this.apiEndpoint = 'http://localhost:8000/api/v1';
    this.isEnabled = true;
    this.sessionId = this.generateSessionId();
    
    this.initializeMonitor();
  }
  
  generateSessionId() {
    return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }
  
  async initializeMonitor() {
    // Load configuration
    const config = await chrome.storage.sync.get(['monitorEnabled', 'apiEndpoint', 'userConsent']);
    
    this.isEnabled = config.monitorEnabled !== false;
    this.apiEndpoint = config.apiEndpoint || this.apiEndpoint;
    
    // Check user consent
    if (!config.userConsent) {
      this.requestUserConsent();
    }
    
    this.setupEventListeners();
  }
  
  setupEventListeners() {
    // Listen for messages from content scripts
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      this.handleMessage(message, sender, sendResponse);
      return true; // Keep message channel open for async response
    });
    
    // Listen for tab updates to track navigation
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.status === 'complete' && this.isAIPlatform(tab.url)) {
        this.trackNavigation(tabId, tab);
      }
    });
    
    // Periodic data sync
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name === 'sync-data') {
        this.syncStoredData();
      }
    });
    
    // Create sync alarm
    chrome.alarms.create('sync-data', { delayInMinutes: 5, periodInMinutes: 5 });
  }
  
  async handleMessage(message, sender, sendResponse) {
    try {
      switch (message.type) {
        case 'TRACK_PROMPT':
          await this.trackPrompt(message.data, sender.tab);
          sendResponse({ success: true });
          break;
          
        case 'TRACK_RESPONSE':
          await this.trackResponse(message.data, sender.tab);
          sendResponse({ success: true });
          break;
          
        case 'SECURITY_ALERT':
          await this.handleSecurityAlert(message.data, sender.tab);
          sendResponse({ success: true });
          break;
          
        default:
          sendResponse({ error: 'Unknown message type' });
      }
    } catch (error) {
      console.error('Error handling message:', error);
      sendResponse({ error: error.message });
    }
  }
  
  isAIPlatform(url) {
    if (!url) return false;
    
    const aiDomains = [
      'openai.com', 'deepseek.com', 'claude.ai', 'anthropic.com',
      'perplexity.ai', 'cohere.ai', 'replicate.com', 'huggingface.co',
      'together.ai', 'mistral.ai'
    ];
    
    return aiDomains.some(domain => url.includes(domain));
  }
  
  async trackPrompt(data, tab) {
    if (!this.isEnabled) return;
    
    const trackingData = {
      type: 'prompt',
      sessionId: this.sessionId,
      timestamp: Date.now(),
      platform: this.extractPlatform(tab.url),
      url: tab.url,
      title: tab.title,
      promptHash: await this.hashSensitiveData(data.prompt),
      promptLength: data.prompt ? data.prompt.length : 0,
      riskIndicators: this.analyzeRisk(data.prompt),
      metadata: {
        userAgent: navigator.userAgent,
        tabId: tab.id
      }
    };
    
    await this.storeData(trackingData);
    
    // Real-time alert check
    if (trackingData.riskIndicators.riskLevel === 'high') {
      this.sendSecurityAlert(trackingData);
    }
  }
  
  async trackResponse(data, tab) {
    if (!this.isEnabled) return;
    
    const trackingData = {
      type: 'response',
      sessionId: this.sessionId,
      timestamp: Date.now(),
      platform: this.extractPlatform(tab.url),
      responseHash: await this.hashSensitiveData(data.response),
      responseLength: data.response ? data.response.length : 0,
      metadata: {
        tabId: tab.id
      }
    };
    
    await this.storeData(trackingData);
  }
  
  analyzeRisk(prompt) {
    const riskIndicators = {
      riskLevel: 'low',
      flags: [],
      score: 0
    };
    
    if (!prompt) return riskIndicators;
    
    const sensitivePatterns = [
      { pattern: /password|secret|key|token/gi, weight: 3, flag: 'credentials' },
      { pattern: /confidential|internal|proprietary/gi, weight: 2, flag: 'confidential' },
      { pattern: /hack|exploit|bypass|vulnerability/gi, weight: 4, flag: 'security_risk' },
      { pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, weight: 5, flag: 'credit_card' },
      { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, weight: 5, flag: 'ssn' },
      { pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, weight: 1, flag: 'email' }
    ];
    
    sensitivePatterns.forEach(({ pattern, weight, flag }) => {
      if (pattern.test(prompt)) {
        riskIndicators.score += weight;
        riskIndicators.flags.push(flag);
      }
    });
    
    if (riskIndicators.score >= 5) {
      riskIndicators.riskLevel = 'high';
    } else if (riskIndicators.score >= 2) {
      riskIndicators.riskLevel = 'medium';
    }
    
    return riskIndicators;
  }
  
  extractPlatform(url) {
    if (!url) return 'unknown';
    
    const platformMap = {
      'openai.com': 'ChatGPT',
      'deepseek.com': 'DeepSeek',
      'claude.ai': 'Claude',
      'anthropic.com': 'Claude',
      'perplexity.ai': 'Perplexity',
      'cohere.ai': 'Cohere',
      'replicate.com': 'Replicate',
      'huggingface.co': 'HuggingFace',
      'together.ai': 'Together',
      'mistral.ai': 'Mistral'
    };
    
    for (const [domain, platform] of Object.entries(platformMap)) {
      if (url.includes(domain)) return platform;
    }
    
    return 'unknown';
  }
  
  async hashSensitiveData(data) {
    if (!data) return null;
    
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }
  
  async storeData(data) {
    try {
      // Store locally first
      const stored = await chrome.storage.local.get(['pendingData']) || {};
      const pendingData = stored.pendingData || [];
      pendingData.push(data);
      
      await chrome.storage.local.set({ pendingData });
      
      // Try to send immediately
      await this.sendToServer(data);
      
    } catch (error) {
      console.error('Error storing data:', error);
    }
  }
  
  async sendToServer(data) {
    const body = JSON.stringify(data);
    const headers = await buildSignedHeaders(body);

    if (!headers) {
      // Unconfigured extension: the request would be rejected, so fail fast
      // and let the caller keep the payload queued for a later retry.
      throw new Error('No extension secret configured; cannot sign request');
    }

    const response = await fetch(`${this.apiEndpoint}/collect`, {
      method: 'POST',
      headers,
      body
    });

    if (!response.ok) {
      throw new Error(`Server responded with ${response.status}`);
    }

    return response.json();
  }
  
  async syncStoredData() {
    try {
      const stored = await chrome.storage.local.get(['pendingData']);
      const pendingData = stored.pendingData || [];
      
      if (pendingData.length === 0) return;
      
      const successful = [];
      
      for (const data of pendingData) {
        try {
          await this.sendToServer(data);
          successful.push(data);
        } catch (error) {
          // Keep failed items for retry
          console.error('Failed to sync data:', error);
        }
      }
      
      // Remove successfully sent items
      if (successful.length > 0) {
        const remaining = pendingData.filter(item => !successful.includes(item));
        await chrome.storage.local.set({ pendingData: remaining });
      }
      
    } catch (error) {
      console.error('Error syncing stored data:', error);
    }
  }
  
  async sendSecurityAlert(data) {
    try {
      const body = JSON.stringify({
        type: 'security_alert',
        severity: 'high',
        data: data,
        timestamp: Date.now()
      });
      const headers = await buildSignedHeaders(body);

      if (headers) {
        await fetch(`${this.apiEndpoint}/alert`, {
          method: 'POST',
          headers,
          body
        });
      }
      
      // Show notification to user
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: 'Security Alert',
        message: 'Potential security risk detected in AI interaction'
      });
      
    } catch (error) {
      console.error('Error sending security alert:', error);
    }
  }
  
  requestUserConsent() {
    // This would typically open a popup or notification
    // For now, we'll use the extension popup
    chrome.action.setBadgeText({ text: '!' });
    chrome.action.setBadgeBackgroundColor({ color: '#ff0000' });
  }
}

// Initialize the security monitor
const securityMonitor = new SecurityMonitor();