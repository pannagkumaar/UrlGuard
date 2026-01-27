/**
 * API Key Management Utility
 * Handles async retrieval of API keys from chrome.storage.local
 */

export interface ApiKeys {
  GOOGLE_SAFE_BROWSING: string;
  VIRUSTOTAL: string;
  PHISHTANK: string;
}

/**
 * Get API keys from chrome.storage.local
 */
export async function getApiKeys(): Promise<ApiKeys> {
  try {
    const result = await chrome.storage.local.get([
      'LS_GOOGLE_SAFE_BROWSING',
      'LS_VIRUSTOTAL',
      'LS_PHISHTANK'
    ]);

    return {
      GOOGLE_SAFE_BROWSING: result.LS_GOOGLE_SAFE_BROWSING || 'YOUR_API_KEY_HERE',
      VIRUSTOTAL: result.LS_VIRUSTOTAL || 'YOUR_API_KEY_HERE',
      PHISHTANK: result.LS_PHISHTANK || 'YOUR_API_KEY_HERE'
    };
  } catch (error) {
    console.error('Error loading API keys:', error);
    return {
      GOOGLE_SAFE_BROWSING: 'YOUR_API_KEY_HERE',
      VIRUSTOTAL: 'YOUR_API_KEY_HERE',
      PHISHTANK: 'YOUR_API_KEY_HERE'
    };
  }
}
