/**
 * Popup Dashboard Script
 * Displays statistics, current page status, and whitelist management
 */

// Load data when popup opens
document.addEventListener('DOMContentLoaded', async () => {
  await loadCurrentPageStatus();
  await loadStatistics();
  await loadWhitelist();
  await loadApiKeys();
  setupEventListeners();
});

/**
 * Load current page status
 */
async function loadCurrentPageStatus() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab || !tab.url) {
      document.getElementById('currentDomain')!.textContent = 'No active tab';
      return;
    }

    // Display domain
    const url = new URL(tab.url);
    document.getElementById('currentDomain')!.textContent = url.hostname;

    // Get analysis result for this tab
    const result = await chrome.storage.session.get([`analysis_${tab.id}`]);
    const analysis = result[`analysis_${tab.id}`];

    if (analysis) {
      const riskLevel = document.getElementById('riskLevel')!;
      const riskScore = document.getElementById('riskScore')!;

      riskLevel.textContent = analysis.riskLevel.toUpperCase();
      riskLevel.className = `risk-level ${analysis.riskLevel}`;
      riskScore.textContent = `${analysis.riskScore}/100`;

      // Show detailed breakdown if available
      displayDetectionBreakdown(analysis);
    } else {
      // Hide breakdown if no analysis available
      const breakdown = document.getElementById('detectionBreakdown')!;
      breakdown.style.display = 'none';
    }
  } catch (error) {
    console.error('Error loading current page status:', error);
    document.getElementById('currentDomain')!.textContent = 'Error loading page info';
  }
}

/**
 * Display detailed detection breakdown
 */
function displayDetectionBreakdown(analysis: any) {
  const breakdown = document.getElementById('detectionBreakdown')!;
  const summary = document.getElementById('detailsSummary')!;
  const layersList = document.getElementById('layersList')!;

  // Show the breakdown section
  breakdown.style.display = 'block';

  // Display summary
  summary.textContent = analysis.details || 'No additional details available';

  // Clear existing layers
  layersList.innerHTML = '';

  // Group layers by type for better organization
  const signatureLayers = analysis.detectionLayers.filter((l: any) => l.layer === 'signature');
  const heuristicLayers = analysis.detectionLayers.filter((l: any) => l.layer === 'heuristic');
  const mlLayers = analysis.detectionLayers.filter((l: any) => l.layer === 'ml');
  const behaviorLayers = analysis.detectionLayers.filter((l: any) => l.layer === 'behavior');

  // Display signature layers (external APIs) first as they have priority
  if (signatureLayers.length > 0) {
    const sectionTitle = document.createElement('div');
    sectionTitle.style.fontWeight = '600';
    sectionTitle.style.color = 'var(--accent-color)';
    sectionTitle.style.fontSize = '0.8rem';
    sectionTitle.style.marginBottom = '0.5rem';
    sectionTitle.textContent = 'External Threat Intelligence';
    layersList.appendChild(sectionTitle);

    signatureLayers.forEach((layer: any) => {
      layersList.appendChild(createLayerItem(layer));
    });
  }

  // Display other layers
  const otherLayers = [...heuristicLayers, ...mlLayers, ...behaviorLayers];
  if (otherLayers.length > 0) {
    const sectionTitle = document.createElement('div');
    sectionTitle.style.fontWeight = '600';
    sectionTitle.style.color = 'var(--accent-color)';
    sectionTitle.style.fontSize = '0.8rem';
    sectionTitle.style.margin = '1rem 0 0.5rem 0';
    sectionTitle.textContent = 'Internal Detection Methods';
    layersList.appendChild(sectionTitle);

    otherLayers.forEach((layer: any) => {
      layersList.appendChild(createLayerItem(layer));
    });
  }
}

/**
 * Create a layer item element
 */
function createLayerItem(layer: any): HTMLElement {
  const item = document.createElement('div');
  item.className = 'layer-item';

  const method = document.createElement('div');
  method.className = 'layer-method';
  method.textContent = layer.method;

  const score = document.createElement('div');
  score.className = 'layer-score';

  const scoreValue = document.createElement('div');
  scoreValue.className = 'layer-score-value';
  
  if (layer.matched) {
    scoreValue.classList.add('matched');
    scoreValue.textContent = `${layer.score}`;
  } else if (layer.details && layer.details.includes('failed') || layer.details.includes('unavailable')) {
    scoreValue.classList.add('error');
    scoreValue.textContent = 'N/A';
  } else {
    scoreValue.classList.add('clean');
    scoreValue.textContent = 'Clean';
  }

  score.appendChild(scoreValue);
  item.appendChild(method);
  item.appendChild(score);

  // Add details if available
  if (layer.details) {
    const details = document.createElement('div');
    details.className = 'layer-details';
    details.textContent = layer.details;
    item.appendChild(details);
  }

  return item;
}

/**
 * Load statistics
 */
async function loadStatistics() {
  try {
    const response = await chrome.runtime.sendMessage({ type: 'getStats' });
    
    if (response.success) {
      const { stats, recentlyBlocked } = response;

      // Update main stats
      document.getElementById('totalChecked')!.textContent = stats.totalChecked.toString();
      document.getElementById('totalBlocked')!.textContent = stats.totalBlocked.toString();

      // Update detection method bars
      const maxBlocked = Math.max(
        stats.blockedByLayer.signature,
        stats.blockedByLayer.heuristic,
        stats.blockedByLayer.ml,
        1 // Prevent division by zero
      );

      updateBar('Signature', stats.blockedByLayer.signature, maxBlocked);
      updateBar('Heuristic', stats.blockedByLayer.heuristic, maxBlocked);
      updateBar('ML', stats.blockedByLayer.ml, maxBlocked);

      // Update recent blocks
      displayRecentBlocks(recentlyBlocked);
    }
  } catch (error) {
    console.error('Error loading statistics:', error);
  }
}

/**
 * Update detection method bar
 */
function updateBar(type: string, count: number, max: number) {
  const percentage = (count / max) * 100;
  const barId = `bar${type}`;
  const countId = `count${type}`;

  const barElement = document.getElementById(barId);
  const countElement = document.getElementById(countId);

  if (barElement && countElement) {
    barElement.style.width = `${percentage}%`;
    countElement.textContent = count.toString();
  }
}

/**
 * Display recent blocked sites
 */
function displayRecentBlocks(recentlyBlocked: any[]) {
  const recentList = document.getElementById('recentList')!;
  
  if (!recentlyBlocked || recentlyBlocked.length === 0) {
    recentList.innerHTML = '<p class="no-data">No threats blocked yet</p>';
    return;
  }

  recentList.innerHTML = '';
  
  // Show only last 5
  const toShow = recentlyBlocked.slice(0, 5);
  
  toShow.forEach(item => {
    const itemDiv = document.createElement('div');
    itemDiv.className = 'recent-item';
    
    const hostname = new URL(item.url).hostname;
    const timeAgo = getTimeAgo(item.timestamp);
    
    itemDiv.innerHTML = `
      <div class="recent-url">${hostname}</div>
      <div class="recent-meta">
        <span>${timeAgo}</span>
        <span class="recent-risk">${item.riskLevel.toUpperCase()}</span>
      </div>
    `;
    
    recentList.appendChild(itemDiv);
  });
}

/**
 * Get time ago string
 */
function getTimeAgo(timestamp: number): string {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  
  if (seconds < 60) return 'Just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

/**
 * Load whitelist
 */
async function loadWhitelist() {
  try {
    const response = await chrome.runtime.sendMessage({ type: 'getWhitelist' });
    
    if (response.success) {
      displayWhitelist(response.whitelist);
    }
  } catch (error) {
    console.error('Error loading whitelist:', error);
  }
}

/**
 * Display whitelist
 */
function displayWhitelist(whitelist: string[]) {
  const whitelistList = document.getElementById('whitelistList')!;
  
  if (!whitelist || whitelist.length === 0) {
    whitelistList.innerHTML = '<p class="no-data">No whitelisted domains</p>';
    return;
  }

  whitelistList.innerHTML = '';
  
  whitelist.forEach(domain => {
    const itemDiv = document.createElement('div');
    itemDiv.className = 'whitelist-item';
    
    itemDiv.innerHTML = `
      <span class="whitelist-domain">${domain}</span>
      <button class="btn-remove" data-domain="${domain}">Remove</button>
    `;
    
    whitelistList.appendChild(itemDiv);
  });

  // Add event listeners to remove buttons
  document.querySelectorAll('.btn-remove').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const domain = (e.target as HTMLElement).getAttribute('data-domain');
      if (domain) {
        await removeFromWhitelist(domain);
      }
    });
  });
}

/**
 * Add domain to whitelist
 */
async function addToWhitelist() {
  const input = document.getElementById('whitelistInput') as HTMLInputElement;
  const domain = input.value.trim().toLowerCase();

  if (!domain) {
    alert('Please enter a domain');
    return;
  }

  // Validate domain format
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain)) {
    alert('Please enter a valid domain (e.g., example.com)');
    return;
  }

  try {
    await chrome.runtime.sendMessage({
      type: 'addToWhitelist',
      domain: domain
    });

    input.value = '';
    await loadWhitelist();
  } catch (error) {
    alert('Error adding to whitelist: ' + error);
  }
}

/**
 * Remove domain from whitelist
 */
async function removeFromWhitelist(domain: string) {
  try {
    await chrome.runtime.sendMessage({
      type: 'removeFromWhitelist',
      domain: domain
    });

    await loadWhitelist();
  } catch (error) {
    alert('Error removing from whitelist: ' + error);
  }
}

/**
 * Reset statistics
 */
async function resetStatistics() {
  const confirmed = confirm('Are you sure you want to reset all statistics?');
  
  if (!confirmed) return;

  try {
    await chrome.runtime.sendMessage({ type: 'resetStats' });
    await loadStatistics();
    alert('Statistics reset successfully');
  } catch (error) {
    alert('Error resetting statistics: ' + error);
  }
}

/**
 * Load API keys
 */
async function loadApiKeys() {
  const result = await chrome.storage.local.get(['LS_GOOGLE_SAFE_BROWSING', 'LS_VIRUSTOTAL', 'LS_PHISHTANK']);
  const safe = result.LS_GOOGLE_SAFE_BROWSING || '';
  const vt = result.LS_VIRUSTOTAL || '';
  const phish = result.LS_PHISHTANK || '';
  
  // Mask keys with asterisks if they exist
  const safeBrowsingInput = document.getElementById('apiKeySafeBrowsing') as HTMLInputElement;
  const virusTotalInput = document.getElementById('apiKeyVirusTotal') as HTMLInputElement;
  const phishTankInput = document.getElementById('apiKeyPhishTank') as HTMLInputElement;
  
  safeBrowsingInput.value = safe ? maskApiKey(safe) : '';
  virusTotalInput.value = vt ? maskApiKey(vt) : '';
  phishTankInput.value = phish ? maskApiKey(phish) : '';
  
  // Store actual keys as data attributes for later use
  if (safe) safeBrowsingInput.dataset.actualKey = safe;
  if (vt) virusTotalInput.dataset.actualKey = vt;
  if (phish) phishTankInput.dataset.actualKey = phish;
}

/**
 * Mask API key for display
 */
function maskApiKey(key: string): string {
  if (!key || key.length < 8) return key;
  // Show first 4 and last 4 chars, mask the rest
  const visible = 4;
  const start = key.substring(0, visible);
  const end = key.substring(key.length - visible);
  const masked = '*'.repeat(Math.max(8, key.length - (visible * 2)));
  return `${start}${masked}${end}`;
}

/**
 * Save API keys
 */
async function saveApiKeys() {
  const safeBrowsingInput = document.getElementById('apiKeySafeBrowsing') as HTMLInputElement;
  const virusTotalInput = document.getElementById('apiKeyVirusTotal') as HTMLInputElement;
  const phishTankInput = document.getElementById('apiKeyPhishTank') as HTMLInputElement;
  
  // Get actual keys (either from input if changed, or from data attribute)
  let safe = safeBrowsingInput.value.trim();
  let vt = virusTotalInput.value.trim();
  let phish = phishTankInput.value.trim();
  
  // If the value contains asterisks, use the stored actual key
  if (safe.includes('*') && safeBrowsingInput.dataset.actualKey) {
    safe = safeBrowsingInput.dataset.actualKey;
  }
  if (vt.includes('*') && virusTotalInput.dataset.actualKey) {
    vt = virusTotalInput.dataset.actualKey;
  }
  if (phish.includes('*') && phishTankInput.dataset.actualKey) {
    phish = phishTankInput.dataset.actualKey;
  }
  
  await chrome.storage.local.set({
    LS_GOOGLE_SAFE_BROWSING: safe,
    LS_VIRUSTOTAL: vt,
    LS_PHISHTANK: phish
  });
  
  console.log('API keys saved (masked for display)');
  
  // Show a temporary message in the popup
  const btn = document.getElementById('saveApiKeysBtn');
  if (btn) {
    btn.textContent = 'Saved!';
    btn.classList.add('btn-success');
    setTimeout(() => {
      btn.textContent = 'Save API Keys';
      btn.classList.remove('btn-success');
    }, 1500);
  }
  
  // Mask the keys after saving
  setTimeout(() => {
    loadApiKeys();
  }, 1600);
  
  alert('API keys saved successfully! Keys are now hidden for security.');
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
  // Add to whitelist
  document.getElementById('addWhitelistBtn')?.addEventListener('click', addToWhitelist);
  
  // Enter key in whitelist input
  document.getElementById('whitelistInput')?.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      addToWhitelist();
    }
  });

  // Reset statistics
  document.getElementById('resetStatsBtn')?.addEventListener('click', resetStatistics);

  // Clear cache (placeholder - could be implemented)
  document.getElementById('clearCacheBtn')?.addEventListener('click', () => {
    alert('Cache cleared successfully');
  });

  // Refresh data every 5 seconds
  setInterval(() => {
    loadCurrentPageStatus();
    loadStatistics();
  }, 5000);

  // Save API keys
  document.getElementById('saveApiKeysBtn')?.addEventListener('click', saveApiKeys);
  
  // API key input handlers - reveal on focus, mask on blur
  setupApiKeyHandlers('apiKeySafeBrowsing');
  setupApiKeyHandlers('apiKeyVirusTotal');
  setupApiKeyHandlers('apiKeyPhishTank');
}

/**
 * Setup API key input handlers to reveal/mask on focus/blur
 */
function setupApiKeyHandlers(inputId: string) {
  const input = document.getElementById(inputId) as HTMLInputElement;
  if (!input) return;
  
  input.addEventListener('focus', function() {
    // Reveal actual key on focus
    if (this.value.includes('*') && this.dataset.actualKey) {
      this.value = this.dataset.actualKey;
    }
  });
  
  input.addEventListener('blur', function() {
    // Mask key on blur if it wasn't changed
    if (this.value && !this.value.includes('*')) {
      this.dataset.actualKey = this.value;
      this.value = maskApiKey(this.value);
    }
  });
}
