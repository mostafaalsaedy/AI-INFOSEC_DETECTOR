// InfoSec AI Monitor - Content Script
class AIContentMonitor {
  constructor() {
    this.platform = this.detectPlatform();
    this.isMonitoring = false;
    this.observerConfig = { 
      childList: true, 
      subtree: true, 
      characterData: true 
    };
    this.lastPrompt = '';
    this.debounceTimeout = null;
    
    this.init();
  }
  
  init() {
    this.setupDOMObserver();
    this.monitorInputs();
    this.showConsentBanner();
    
    console.log(`InfoSec AI Monitor active on ${this.platform}`);
  }
  
  detectPlatform() {
    const hostname = window.location.hostname;
    
    const platforms = {
      'openai.com': 'ChatGPT',
      'chat.openai.com': 'ChatGPT',
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
    
    for (const [domain, platform] of Object.entries(platforms)) {
      if (hostname.includes(domain)) return platform;
    }
    
    return 'Unknown';
  }
  
  setupDOMObserver() {
    this.observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === 'childList') {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              this.checkForNewInputs(node);
              this.checkForResponses(node);
            }
          });
        }
      });
    });
    
    this.observer.observe(document.body, this.observerConfig);
  }
  
  checkForNewInputs(element) {
    // Common selectors for AI platform input fields
    const inputSelectors = [
      'textarea[placeholder*="message"], textarea[placeholder*="prompt"], textarea[placeholder*="ask"]',
      'input[type="text"][placeholder*="message"], input[type="text"][placeholder*="prompt"]',
      '[contenteditable="true"]',
      'textarea.form-control',
      'textarea#prompt-textarea',
      '.ProseMirror',
      '[data-testid*="input"], [data-testid*="prompt"]'
    ];
    
    inputSelectors.forEach(selector => {
      const inputs = element.querySelectorAll ? 
        element.querySelectorAll(selector) : 
        (element.matches && element.matches(selector) ? [element] : []);
        
      inputs.forEach(input => this.attachInputListener(input));
    });
  }
  
  checkForResponses(element) {
    // Look for AI response elements
    const responseSelectors = [
      '.markdown-content, .message-content, .response-text',
      '[data-testid*="response"], [data-testid*="message"]',
      '.chat-message, .conversation-item',
      '.prose, .response-body'
    ];
    
    responseSelectors.forEach(selector => {
      const responses = element.querySelectorAll ? 
        element.querySelectorAll(selector) : 
        (element.matches && element.matches(selector) ? [element] : []);
        
      responses.forEach(response => this.processResponse(response));
    });
  }
  
  attachInputListener(input) {
    if (input.hasAttribute('data-monitored')) return;
    input.setAttribute('data-monitored', 'true');
    
    // Monitor input changes
    const handleInput = () => {
      clearTimeout(this.debounceTimeout);
      this.debounceTimeout = setTimeout(() => {
        this.processInput(input);
      }, 1000); // Debounce for 1 second
    };
    
    input.addEventListener('input', handleInput);
    input.addEventListener('paste', handleInput);
    
    // Monitor form submission
    const form = input.closest('form');
    if (form && !form.hasAttribute('data-monitored')) {
      form.setAttribute('data-monitored', 'true');
      form.addEventListener('submit', () => {
        this.processSubmission(input);
      });
    }
    
    // Monitor enter key for non-form inputs
    input.addEventListener('keydown', (e) => {
      if ((e.key === 'Enter' && !e.shiftKey) || (e.key === 'Enter' && e.ctrlKey)) {
        setTimeout(() => this.processSubmission(input), 100);
      }
    });
  }
  
  processInput(input) {
    const content = this.getInputContent(input);
    if (!content || content === this.lastPrompt) return;
    
    this.lastPrompt = content;
    
    // Basic security analysis
    const riskAnalysis = this.analyzeContent(content);
    
    if (riskAnalysis.hasRisks) {
      this.showWarning(input, riskAnalysis);
    }
  }
  
  processSubmission(input) {
    const content = this.getInputContent(input);
    if (!content) return;
    
    // Send to background script
    chrome.runtime.sendMessage({
      type: 'TRACK_PROMPT',
      data: {
        prompt: content,
        platform: this.platform,
        timestamp: Date.now(),
        url: window.location.href
      }
    }).catch(error => {
      console.error('Error sending prompt data:', error);
    });
    
    // Clear the stored prompt
    this.lastPrompt = '';
  }
  
  processResponse(responseElement) {
    if (responseElement.hasAttribute('data-processed')) return;
    responseElement.setAttribute('data-processed', 'true');
    
    const content = responseElement.textContent || responseElement.innerText;
    if (!content) return;
    
    // Send to background script
    chrome.runtime.sendMessage({
      type: 'TRACK_RESPONSE',
      data: {
        response: content,
        platform: this.platform,
        timestamp: Date.now(),
        url: window.location.href
      }
    }).catch(error => {
      console.error('Error sending response data:', error);
    });
  }
  
  getInputContent(input) {
    if (input.tagName === 'TEXTAREA' || input.tagName === 'INPUT') {
      return input.value;
    } else if (input.contentEditable === 'true') {
      return input.textContent || input.innerText;
    }
    return '';
  }
  
  analyzeContent(content) {
    const risks = {
      hasRisks: false,
      riskTypes: [],
      suggestions: []
    };
    
    // Pattern matching for sensitive data
    const sensitivePatterns = [
      {
        pattern: /\b(?:\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|\d{4}[-\s]?\d{6}[-\s]?\d{5})\b/g,
        type: 'credit_card',
        message: 'Potential credit card number detected'
      },
      {
        pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
        type: 'ssn',
        message: 'Potential Social Security Number detected'
      },
      {
        pattern: /\b(?:password|passwd|pwd)\s*[:=]\s*\S+/gi,
        type: 'password',
        message: 'Password information detected'
      },
      {
        pattern: /\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*\S+/gi,
        type: 'api_key',
        message: 'API key or token detected'
      },
      {
        pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
        type: 'email',
        message: 'Email address detected'
      }
    ];
    
    sensitivePatterns.forEach(({ pattern, type, message }) => {
      if (pattern.test(content)) {
        risks.hasRisks = true;
        risks.riskTypes.push(type);
        risks.suggestions.push(message);
      }
    });
    
    return risks;
  }
  
  showWarning(input, riskAnalysis) {
    // Remove existing warnings
    const existingWarning = input.parentElement.querySelector('.security-warning');
    if (existingWarning) existingWarning.remove();
    
    const warning = document.createElement('div');
    warning.className = 'security-warning';
    warning.innerHTML = `
      <div style="
        background: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 4px;
        padding: 8px;
        margin-top: 4px;
        font-size: 12px;
        color: #856404;
      ">
        <strong>⚠️ Security Warning:</strong> ${riskAnalysis.suggestions.join(', ')}
      </div>
    `;
    
    input.parentElement.appendChild(warning);
    
    // Auto-remove after 10 seconds
    setTimeout(() => {
      if (warning.parentElement) {
        warning.remove();
      }
    }, 10000);
  }
  
  showConsentBanner() {
    // Check if user has already consented
    chrome.storage.sync.get(['userConsent']).then(result => {
      if (result.userConsent) return;
      
      const banner = document.createElement('div');
      banner.className = 'infosec-consent-banner';
      banner.innerHTML = `
        <div style="
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          background: #1a73e8;
          color: white;
          padding: 12px;
          z-index: 10000;
          text-align: center;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          font-size: 14px;
          box-shadow: 0 2px 8px rgba(0,0,0,0.15);
        ">
          <div style="max-width: 1200px; margin: 0 auto;">
            <span>InfoSec AI Monitor is active. Your AI interactions are being monitored for security compliance.</span>
            <button id="consent-accept" style="
              background: white;
              color: #1a73e8;
              border: none;
              padding: 6px 16px;
              margin-left: 16px;
              border-radius: 4px;
              cursor: pointer;
              font-weight: 500;
            ">I Understand</button>
            <button id="consent-learn-more" style="
              background: transparent;
              color: white;
              border: 1px solid white;
              padding: 6px 16px;
              margin-left: 8px;
              border-radius: 4px;
              cursor: pointer;
            ">Learn More</button>
          </div>
        </div>
      `;
      
      document.body.appendChild(banner);
      
      // Handle consent
      banner.querySelector('#consent-accept').addEventListener('click', () => {
        chrome.storage.sync.set({ userConsent: true, consentDate: Date.now() });
        banner.remove();
      });
      
      banner.querySelector('#consent-learn-more').addEventListener('click', () => {
        window.open('https://your-domain.com/privacy-policy', '_blank');
      });
    });
  }
}

// Initialize only if not already initialized
if (!window.aiContentMonitor) {
  window.aiContentMonitor = new AIContentMonitor();
}