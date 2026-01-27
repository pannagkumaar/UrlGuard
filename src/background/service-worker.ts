/**
 * Background Service Worker (Manifest V3)
 * Handles URL interception, threat analysis, and blocking
 */

import { ThreatAnalyzer } from '../detection/threat-analyzer';
import { Statistics, BlockedSite, WhitelistEntry } from '../types/types';

// Statistics tracking
let stats: Statistics = {
  totalChecked: 0,
  totalBlocked: 0,
  blockedByLayer: {
    signature: 0,
    heuristic: 0,
    ml: 0,
    behavior: 0
  },
  riskDistribution: {
    safe: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0
  },
  lastReset: Date.now()
};

// Recently blocked sites
const recentlyBlocked: BlockedSite[] = [];
const MAX_RECENT_BLOCKED = 100;

/**
 * Initialize extension
 */
chrome.runtime.onInstalled.addListener(async () => {
  console.log('LinkShield installed');
  
  // Load statistics from storage
  const stored = await chrome.storage.local.get(['stats', 'whitelist']);
  if (stored.stats) {
    stats = stored.stats;
  }
  
  if (stored.whitelist) {
    stored.whitelist.forEach((domain: string) => ThreatAnalyzer.addToWhitelist(domain));
  }

  // Set up alarms for periodic tasks
  chrome.alarms.create('clearCache', { periodInMinutes: 60 });
  chrome.alarms.create('saveStats', { periodInMinutes: 5 });
});

/**
 * Intercept web requests before they're made
 */
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    // Skip non-main frame requests for performance
    if (details.type !== 'main_frame' && details.type !== 'sub_frame') {
      return;
    }

    // Skip chrome:// and extension URLs
    if (details.url.startsWith('chrome://') || 
        details.url.startsWith('chrome-extension://') ||
        details.url.startsWith('edge://')) {
      return;
    }

    // Analyze URL asynchronously and handle blocking
    (async () => {
      try {
        // Analyze URL
        const result = await ThreatAnalyzer.analyze(details.url);
        
        // Update statistics
        stats.totalChecked++;
        stats.riskDistribution[result.riskLevel]++;

        // Store analysis result for popup
        await chrome.storage.session.set({
          [`analysis_${details.tabId}`]: result
        });

        // Block if malicious
        if (result.isMalicious) {
          stats.totalBlocked++;
          
          // Update blocked by layer stats
          const layers = result.detectionLayers.filter(l => l.matched);
          for (const layer of layers) {
            if (layer.layer in stats.blockedByLayer) {
              stats.blockedByLayer[layer.layer]++;
            }
          }

          // Add to recently blocked
          recentlyBlocked.unshift({
            url: details.url,
            timestamp: Date.now(),
            riskLevel: result.riskLevel,
            reason: result.details
          });

          if (recentlyBlocked.length > MAX_RECENT_BLOCKED) {
            recentlyBlocked.pop();
          }

          // Store blocked info for the blocked page
          await chrome.storage.session.set({
            [`blocked_${details.tabId}`]: result
          });

          // Navigate to blocked page
          const blockedPageUrl = chrome.runtime.getURL('blocked.html') + 
            `?url=${encodeURIComponent(details.url)}&tabId=${details.tabId}`;
          
          chrome.tabs.update(details.tabId, { url: blockedPageUrl });
        }

      } catch (error) {
        console.error('Error in webRequest handler:', error);
      }
    })();
  },
  { urls: ['<all_urls>'] }
);

/**
 * Handle navigation events
 */
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only process main frame navigations
  if (details.frameId !== 0) return;

  // Update badge with risk level
  const stored = await chrome.storage.session.get([`analysis_${details.tabId}`]);
  if (stored[`analysis_${details.tabId}`]) {
    const result = stored[`analysis_${details.tabId}`];
    updateBadge(details.tabId, result.riskLevel);
  }
});

/**
 * Update extension badge
 */
function updateBadge(tabId: number, riskLevel: string): void {
  const colors: { [key: string]: string } = {
    safe: '#00AA00',
    low: '#FFD700',
    medium: '#FFA500',
    high: '#FF4500',
    critical: '#FF0000'
  };

  const labels: { [key: string]: string } = {
    safe: '✓',
    low: '!',
    medium: '!!',
    high: '!!!',
    critical: '🚨'
  };

  chrome.action.setBadgeBackgroundColor({ color: colors[riskLevel] || '#808080', tabId });
  chrome.action.setBadgeText({ text: labels[riskLevel] || '', tabId });
}

/**
 * Handle messages from content scripts and popup
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      switch (message.type) {
        case 'analyzeURL':
          const result = await ThreatAnalyzer.analyze(message.url);
          sendResponse({ success: true, result });
          break;

        case 'getStats':
          sendResponse({ success: true, stats, recentlyBlocked });
          break;

        case 'resetStats':
          stats = {
            totalChecked: 0,
            totalBlocked: 0,
            blockedByLayer: { signature: 0, heuristic: 0, ml: 0, behavior: 0 },
            riskDistribution: { safe: 0, low: 0, medium: 0, high: 0, critical: 0 },
            lastReset: Date.now()
          };
          await chrome.storage.local.set({ stats });
          sendResponse({ success: true });
          break;

        case 'addToWhitelist':
          ThreatAnalyzer.addToWhitelist(message.domain);
          const whitelist = ThreatAnalyzer.getWhitelist();
          await chrome.storage.local.set({ whitelist });
          sendResponse({ success: true });
          break;

        case 'removeFromWhitelist':
          ThreatAnalyzer.removeFromWhitelist(message.domain);
          const updatedWhitelist = ThreatAnalyzer.getWhitelist();
          await chrome.storage.local.set({ whitelist: updatedWhitelist });
          sendResponse({ success: true });
          break;

        case 'getWhitelist':
          sendResponse({ success: true, whitelist: ThreatAnalyzer.getWhitelist() });
          break;

        case 'proceedAnyway':
          // User chose to proceed to blocked site
          if (message.tabId) {
            await chrome.storage.session.remove([`blocked_${message.tabId}`]);
            chrome.tabs.update(message.tabId, { url: message.url });
          }
          sendResponse({ success: true });
          break;

        default:
          sendResponse({ success: false, error: 'Unknown message type' });
      }
    } catch (error) {
      console.error('Error handling message:', error);
      sendResponse({ 
        success: false, 
        error: error instanceof Error ? error.message : 'Unknown error' 
      });
    }
  })();
  
  return true; // Keep message channel open for async response
});

/**
 * Handle alarms
 */
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'clearCache') {
    ThreatAnalyzer.clearCache();
    console.log('Cache cleared');
  } else if (alarm.name === 'saveStats') {
    chrome.storage.local.set({ stats });
  }
});

/**
 * Handle tab updates
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && tab.url) {
    // Reset badge when page starts loading
    chrome.action.setBadgeText({ text: '...', tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#808080', tabId });
  }
});

/**
 * Clean up when tab is closed
 */
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove([`analysis_${tabId}`, `blocked_${tabId}`]);
});

console.log('LinkShield service worker loaded');
