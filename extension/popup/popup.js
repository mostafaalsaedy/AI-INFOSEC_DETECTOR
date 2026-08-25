// InfoSec AI Monitor - Popup JavaScript
class PopupController {
  constructor() {
    this.isMonitoring = true;
    this.sessionStats = {
      prompts: 0,
      alerts: 0,
      platforms: new Set()
    };
    
    this.init();
  }
  
  async init() {
    await this.loadSettings();
    this.setupEventListeners();
    this.updateUI();
    this.checkConsent();
    this.loadSessionStats();
    this.detectCurrentPlatform();
  }
  
  async loadSettings() {
    try {
      const settings = await chrome.storage.sync.get([
        'monitorEnabled',
        'userConsent',
        'apiEndpoint'
      ]);
      
      this.isMonitoring = settings.monitorEnabled !== false;
    } catch (error) {
      console.error('Error loading settings:', error);
    }
  }
  
  setupEventListeners() {
    // Toggle monitoring
    document.getElementById('toggle-monitoring').addEventListener('click', () => {
      this.toggleMonitoring();
    });
    
    // View dashboard
    document.getElementById('view-dashboard').addEventListener('click', () => {
      this.openDashboard();
    });
    
    // Consent actions
    document.getElementById('consent-accept').addEventListener('click', () => {
      this.acceptConsent();
    });
    
    document.getElementById('privacy-policy').addEventListener('click', (e) => {
      e.preventDefault();
      this.openPrivacyPolicy();
    });
    
    // Footer links
    document.getElementById('settings-link').addEventListener('click', (e) => {
      e.preventDefault();
      this.openSettings();
    });
    
    document.getElementById('help-link').addEventListener('click', (e) => {
      e.preventDefault();
      this.openHelp();
    });
  }
  
  async toggleMonitoring() {
    try {
      this.isMonitoring = !this.isMonitoring;
      
      await chrome.storage.sync.set({
        monitorEnabled: this.isMonitoring
      });
      
      // Notify background script
      chrome.runtime.sendMessage({
        type: 'TOGGLE_MONITORING',
        enabled: this.isMonitoring
      });
      
      this.updateUI();
      
    } catch (error) {
      console.error('Error toggling monitoring:', error);
    }
  }
  
  updateUI() {
    const statusIndicator = document.getElementById('status-indicator');
    const statusDot = statusIndicator.querySelector('.status-dot');
    const statusText = document.getElementById('status-text');
    const toggleButton = document.getElementById('toggle-monitoring');
    const toggleText = document.getElementById('toggle-text');
    
    if (this.isMonitoring) {
      statusDot.className = 'status-dot';
      statusText.textContent = 'Monitoring Active';
      statusText.className = '';
      toggleText.textContent = 'Pause Monitoring';
    } else {
      statusDot.className = 'status-dot inactive';
      statusText.textContent = 'Monitoring Paused';
      statusText.className = 'inactive';
      toggleText.textContent = 'Resume Monitoring';
    }
  }
  
  async checkConsent() {
    try {
      const settings = await chrome.storage.sync.get(['userConsent']);
      
      if (!settings.userConsent) {
        document.getElementById('consent-section').style.display = 'block';
      }
    } catch (error) {
      console.error('Error checking consent:', error);
    }
  }
  
  async acceptConsent() {
    try {
      await chrome.storage.sync.set({
        userConsent: true,
        consentDate: Date.now()
      });
      
      document.getElementById('consent-section').style.display = 'none';
      
    } catch (error) {
      console.error('Error accepting consent:', error);
    }
  }
  
  async loadSessionStats() {
    try {
      // Get stored session data
      const stored = await chrome.storage.local.get(['sessionStats']);
      
      if (stored.sessionStats) {
        this.sessionStats = {
          ...this.sessionStats,
          ...stored.sessionStats,
          platforms: new Set(stored.sessionStats.platforms || [])
        };
      }
      
      // Update display
      document.getElementById('prompts-count').textContent = this.sessionStats.prompts;
      document.getElementById('alerts-count').textContent = this.sessionStats.alerts;
      document.getElementById('platforms-count').textContent = this.sessionStats.platforms.size;
      
    } catch (error) {
      console.error('Error loading session stats:', error);
    }
  }
  
  async detectCurrentPlatform() {
    try {
      // Get active tab
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      
      if (tab && tab.url) {
        const platform = this.extractPlatformFromUrl(tab.url);
        document.getElementById('current-platform').textContent = platform;
        
        // Add to platforms set if it's an AI platform
        if (platform !== 'Not an AI Platform') {
          this.sessionStats.platforms.add(platform);
          document.getElementById('platforms-count').textContent = this.sessionStats.platforms.size;
          
          await this.saveSessionStats();
        }
      }
      
    } catch (error) {
      console.error('Error detecting platform:', error);
      document.getElementById('current-platform').textContent = 'Unknown';
    }
  }
  
  extractPlatformFromUrl(url) {
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
    
    return 'Not an AI Platform';
  }
  
  async saveSessionStats() {
    try {
      await chrome.storage.local.set({
        sessionStats: {
          ...this.sessionStats,
          platforms: Array.from(this.sessionStats.platforms)
        }
      });
    } catch (error) {
      console.error('Error saving session stats:', error);
    }
  }
  
  openDashboard() {
    chrome.tabs.create({
      url: 'https://your-domain.com/dashboard'
    });
  }
  
  openPrivacyPolicy() {
    chrome.tabs.create({
      url: 'https://your-domain.com/privacy-policy'
    });
  }
  
  openSettings() {
    chrome.runtime.openOptionsPage();
  }
  
  openHelp() {
    chrome.tabs.create({
      url: 'https://your-domain.com/help'
    });
  }
}

// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new PopupController();
});

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'STATS_UPDATE') {
    // Update stats display
    const { prompts, alerts, platforms } = message.data;
    
    document.getElementById('prompts-count').textContent = prompts || 0;
    document.getElementById('alerts-count').textContent = alerts || 0;
    document.getElementById('platforms-count').textContent = platforms || 0;
    
    // Update status if there are alerts
    if (alerts > 0) {
      const statusDot = document.querySelector('.status-dot');
      const statusText = document.getElementById('status-text');
      
      statusDot.className = 'status-dot alert';
      statusText.textContent = `${alerts} Security Alert${alerts > 1 ? 's' : ''}`;
      statusText.className = 'alert';
    }
  }
});