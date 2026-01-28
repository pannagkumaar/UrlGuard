/**
 * Content Script - Layer 4: Page Behavior Analysis
 * Detects credential harvesting, fake login forms, and suspicious JavaScript
 */

// Detect link clicks and warn users
document.addEventListener('click', async (event) => {
  const target = event.target as HTMLElement;
  
  // Check if clicked element is a link or contains a link
  const link = target.closest('a');
  if (!link || !link.href) return;

  // Skip internal links
  if (link.href.startsWith('#') || link.href.startsWith('javascript:')) return;

  // Quick analysis for suspicious links
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'analyzeURL',
      url: link.href
    });

    if (response.success && response.result.isMalicious) {
      // Warn user about suspicious link
      event.preventDefault();
      event.stopPropagation();

      const proceed = confirm(
        `⚠️ WARNING: This link may be dangerous!\n\n` +
        `Risk Level: ${response.result.riskLevel.toUpperCase()}\n` +
        `Reason: ${response.result.details}\n\n` +
        `Do you want to proceed anyway?`
      );

      if (!proceed) {
        console.log('[LinkShield] Blocked suspicious link click:', link.href);
      } else {
        // User chose to proceed
        window.location.href = link.href;
      }
    }
  } catch (error) {
    console.error('[LinkShield] Error analyzing link:', error);
  }
}, true);

/**
 * Detect fake login forms
 */
function detectFakeLoginForms(): void {
  const forms = document.querySelectorAll('form');
  
  forms.forEach((form) => {
    const inputs = form.querySelectorAll('input');
    let hasPassword = false;
    let hasEmail = false;

    inputs.forEach((input) => {
      const type = input.type.toLowerCase();
      const name = input.name.toLowerCase();
      const id = input.id.toLowerCase();

      if (type === 'password') hasPassword = true;
      if (type === 'email' || name.includes('email') || id.includes('email')) hasEmail = true;
      if (name.includes('user') || name.includes('login') || id.includes('user')) hasEmail = true;
    });

    // If form has password and email/username fields, check if it's legitimate
    if (hasPassword && hasEmail) {
      const isHTTPS = window.location.protocol === 'https:';
      const hostname = window.location.hostname;

      // Warn if login form on HTTP
      if (!isHTTPS) {
        form.style.border = '3px solid red';
        form.style.padding = '10px';
        
        const warning = document.createElement('div');
        warning.style.cssText = 'background: #ff4444; color: white; padding: 10px; margin: 10px 0; border-radius: 5px; font-weight: bold;';
        warning.textContent = '⚠️ WARNING: This login form is not secure (HTTP). Your credentials may be intercepted!';
        form.parentElement?.insertBefore(warning, form);

        console.warn('[LinkShield] Insecure login form detected');
      }

      // Check for suspicious form action
      const action = form.action;
      if (action && !action.includes(hostname)) {
        console.warn('[LinkShield] Login form submits to different domain:', action);
      }
    }
  });
}

/**
 * Detect hidden input fields (potential credential harvesting)
 */
function detectHiddenFields(): void {
  const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
  
  hiddenInputs.forEach((input) => {
    const name = (input as HTMLInputElement).name.toLowerCase();
    const suspiciousNames = ['password', 'credit', 'card', 'ssn', 'social'];
    
    if (suspiciousNames.some(s => name.includes(s))) {
      console.warn('[LinkShield] Suspicious hidden input field detected:', name);
    }
  });
}

/**
 * Detect brand impersonation in page content
 */
function detectBrandImpersonation(): void {
  const pageText = document.body.innerText.toLowerCase();
  const pageTitle = document.title.toLowerCase();
  const hostname = window.location.hostname.toLowerCase();

  // Trusted domains that legitimately reference other brands
  const trustedDomains = [
    'github.com', 'stackoverflow.com', 'reddit.com', 'wikipedia.org',
    'medium.com', 'youtube.com', 'twitter.com', 'linkedin.com',
    'news.google.com', 'techcrunch.com', 'verge.com', 'arstechnica.com'
  ];

  // Skip detection on trusted domains to prevent false positives
  if (trustedDomains.some(domain => hostname.endsWith(domain))) {
    return;
  }

  const brands = [
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook',
    'netflix', 'instagram', 'bank', 'chase', 'wellsfargo'
  ];

  for (const brand of brands) {
    // Check if page mentions brand prominently but domain doesn't match
    // Require both high frequency AND suspicious context to reduce false positives
    const textCount = (pageText.match(new RegExp(brand, 'gi')) || []).length;
    const inTitle = pageTitle.includes(brand);
    const hasLoginForm = document.querySelector('input[type="password"]') !== null;
    const hasPaymentForm = document.querySelector('input[name*="card"], input[name*="payment"]') !== null;
    
    // Only flag if there's strong evidence of impersonation attempt
    const strongEvidence = (textCount > 5 || (inTitle && textCount > 2)) && 
                          (hasLoginForm || hasPaymentForm) && 
                          !hostname.includes(brand);
    
    if (strongEvidence) {
      console.warn(`[LinkShield] Potential ${brand} impersonation detected`);
      
      // Add warning banner
      const banner = document.createElement('div');
      banner.id = 'linkshield-warning-banner';
      banner.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        background: linear-gradient(135deg, #ff4444, #cc0000);
        color: white;
        padding: 15px;
        text-align: center;
        font-size: 16px;
        font-weight: bold;
        z-index: 999999;
        box-shadow: 0 2px 10px rgba(0,0,0,0.3);
      `;
      banner.innerHTML = `
        ⚠️ WARNING: This site may be impersonating ${brand.toUpperCase()}. 
        Official ${brand} sites use ${brand}.com domain.
        <button id="linkshield-close-banner" style="margin-left: 20px; padding: 5px 15px; background: white; color: #cc0000; border: none; border-radius: 3px; cursor: pointer; font-weight: bold;">
          Close
        </button>
      `;
      
      document.body.insertBefore(banner, document.body.firstChild);
      
      document.getElementById('linkshield-close-banner')?.addEventListener('click', () => {
        banner.remove();
      });
      
      break; // Only show one warning
    }
  }
}

/**
 * Detect suspicious JavaScript
 */
function detectSuspiciousJS(): void {
  // Look for common phishing/malware patterns in inline scripts
  const scripts = document.querySelectorAll('script');
  
  scripts.forEach((script) => {
    const content = script.textContent || '';
    
    // Suspicious patterns
    const patterns = [
      /eval\(/i,
      /document\.write/i,
      /window\.location\s*=/i,
      /fromCharCode/i,
      /atob\(/i, // base64 decode
      /String\.fromCharCode/i
    ];

    const matchedPatterns = patterns.filter(p => p.test(content));
    
    if (matchedPatterns.length >= 2) {
      console.warn('[LinkShield] Suspicious JavaScript patterns detected');
    }
  });
}

/**
 * Monitor form submissions
 */
document.addEventListener('submit', (event) => {
  const form = event.target as HTMLFormElement;
  
  // Check if form is submitting to external domain
  const formAction = form.action;
  const currentHost = window.location.hostname;
  
  try {
    const actionURL = new URL(formAction, window.location.href);
    
    if (actionURL.hostname !== currentHost) {
      const proceed = confirm(
        `⚠️ WARNING: This form submits data to a different website!\n\n` +
        `Current site: ${currentHost}\n` +
        `Form submits to: ${actionURL.hostname}\n\n` +
        `This could be a phishing attempt. Proceed anyway?`
      );
      
      if (!proceed) {
        event.preventDefault();
        console.log('[LinkShield] Blocked form submission to external domain');
      }
    }
  } catch (error) {
    console.error('[LinkShield] Error checking form action:', error);
  }
}, true);

/**
 * Run all page analysis on load
 */
function runPageAnalysis(): void {
  setTimeout(() => {
    try {
      detectFakeLoginForms();
      detectHiddenFields();
      detectBrandImpersonation();
      detectSuspiciousJS();
    } catch (error) {
      console.error('[LinkShield] Error in page analysis:', error);
    }
  }, 1000); // Wait for page to fully load
}

// Run analysis when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', runPageAnalysis);
} else {
  runPageAnalysis();
}

// Also run when new content is dynamically added
function setupMutationObserver() {
  if (!document.body) {
    // Wait for body to be available
    setTimeout(setupMutationObserver, 100);
    return;
  }

  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.addedNodes.length > 0) {
        // Check if any forms were added
        mutation.addedNodes.forEach((node) => {
          if (node instanceof HTMLElement) {
            if (node.tagName === 'FORM' || node.querySelector('form')) {
              detectFakeLoginForms();
            }
          }
        });
      }
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

setupMutationObserver();

console.log('[LinkShield] Content script loaded and monitoring page');
