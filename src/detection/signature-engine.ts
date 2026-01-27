/**
 * Layer 1: Signature-Based Detection
 * Integration with threat intelligence APIs
 */

import { CONFIG } from '../config/config';
import { APIResponse, DetectionLayer } from '../types/types';
import { getApiKeys } from '../utils/api-keys';

export class SignatureEngine {
  private static safeBrowsingCache = new Map<string, { malicious: boolean; timestamp: number }>();
  private static rateLimitCounters = new Map<string, { count: number; resetTime: number }>();

  /**
   * Check URL against Google Safe Browsing API
   */
  public static async checkSafeBrowsing(url: string): Promise<APIResponse> {
    try {
      // Check cache first
      const cached = this.safeBrowsingCache.get(url);
      if (cached && Date.now() - cached.timestamp < CONFIG.CACHE.SAFE_URL_TTL) {
        return {
          success: true,
          malicious: cached.malicious,
          source: 'Google Safe Browsing (cached)'
        };
      }

      // Check rate limit
      if (!this.checkRateLimit('safe_browsing', CONFIG.RATE_LIMITS.SAFE_BROWSING_PER_MINUTE)) {
        return {
          success: false,
          malicious: false,
          source: 'Google Safe Browsing',
          error: 'Rate limit exceeded'
        };
      }

      // Make API request
      const apiKeys = await getApiKeys();
      const apiKey = apiKeys.GOOGLE_SAFE_BROWSING;
      if (apiKey === 'YOUR_API_KEY_HERE') {
        // Fallback to local blacklist check
        return this.checkLocalBlacklist(url);
      }

      const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
      const requestBody = {
        client: {
          clientId: 'linkshield',
          clientVersion: '1.0.0'
        },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }]
        }
      };

      const response = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
      }

      const data = await response.json();
      const malicious = data.matches && data.matches.length > 0;

      // Cache result
      this.safeBrowsingCache.set(url, { malicious, timestamp: Date.now() });

      return {
        success: true,
        malicious,
        source: 'Google Safe Browsing',
        details: data.matches || []
      };
    } catch (error) {
      console.error('Safe Browsing API error:', error);
      return {
        success: false,
        malicious: false,
        source: 'Google Safe Browsing',
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Check against local blacklist (fallback)
   */
  private static async checkLocalBlacklist(url: string): Promise<APIResponse> {
    try {
      const hostname = new URL(url).hostname.toLowerCase();
      
      // Common malicious patterns
      const blacklistPatterns = [
        /phishing/i,
        /malware/i,
        /scam/i,
        /fake.*login/i,
        /secure.*verify/i,
        /account.*suspend/i
      ];

      const isBlacklisted = blacklistPatterns.some(pattern => pattern.test(url));

      return {
        success: true,
        malicious: isBlacklisted,
        source: 'Local Blacklist',
        details: isBlacklisted ? 'Matched local blacklist pattern' : 'Not in local blacklist'
      };
    } catch (error) {
      return {
        success: false,
        malicious: false,
        source: 'Local Blacklist',
        error: 'Error checking local blacklist'
      };
    }
  }

  /**
   * Check URL against PhishTank database
   */
  public static async checkPhishTank(url: string): Promise<APIResponse> {
    try {
      const apiKeys = await getApiKeys();
      const apiKey = apiKeys.PHISHTANK;
      
      // Skip if no API key configured
      if (apiKey === 'YOUR_API_KEY_HERE') {
        return {
          success: true,
          malicious: false,
          source: 'PhishTank',
          details: 'API key not configured'
        };
      }

      // PhishTank API endpoint
      const encodedUrl = encodeURIComponent(url);
      const apiUrl = `https://checkurl.phishtank.com/checkurl/`;

      const formData = new FormData();
      formData.append('url', url);
      formData.append('format', 'json');
      formData.append('app_key', apiKey);

      const response = await fetch(apiUrl, {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        // Silently fail and continue with other detection methods
        return {
          success: false,
          malicious: false,
          source: 'PhishTank',
          error: `API unavailable (${response.status})`
        };
      }

      const data = await response.json();
      
      return {
        success: true,
        malicious: data.results?.in_database === true && data.results?.valid === true,
        source: 'PhishTank',
        details: data.results
      };
    } catch (error) {
      console.error('PhishTank API error:', error);
      return {
        success: false,
        malicious: false,
        source: 'PhishTank',
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Check URL against VirusTotal
   */
  public static async checkVirusTotal(url: string): Promise<APIResponse> {
    try {
      const apiKeys = await getApiKeys();
      const apiKey = apiKeys.VIRUSTOTAL;
      if (apiKey === 'YOUR_API_KEY_HERE') {
        return {
          success: false,
          malicious: false,
          source: 'VirusTotal',
          error: 'API key not configured'
        };
      }

      // Check rate limit
      if (!this.checkRateLimit('virustotal', CONFIG.RATE_LIMITS.VIRUSTOTAL_PER_DAY)) {
        return {
          success: false,
          malicious: false,
          source: 'VirusTotal',
          error: 'Rate limit exceeded'
        };
      }

      // Encode URL to base64
      const urlId = btoa(url).replace(/=/g, '');
      const apiUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;

      const response = await fetch(apiUrl, {
        headers: {
          'x-apikey': apiKey
        }
      });

      if (!response.ok) {
        throw new Error(`VirusTotal API error: ${response.status}`);
      }

      const data = await response.json();
      const stats = data.data?.attributes?.last_analysis_stats;
      
      // Consider malicious if ANY engine flags it as malicious or suspicious
      const maliciousCount = (stats?.malicious || 0) + (stats?.suspicious || 0);
      const malicious = maliciousCount > 0;

      return {
        success: true,
        malicious: malicious,
        source: 'VirusTotal',
        details: { ...stats, totalDetections: maliciousCount }
      };
    } catch (error) {
      console.error('VirusTotal API error:', error);
      return {
        success: false,
        malicious: false,
        source: 'VirusTotal',
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Aggregate results from multiple APIs
   */
  public static async checkAllAPIs(url: string): Promise<DetectionLayer[]> {
    const results = await Promise.allSettled([
      this.checkSafeBrowsing(url),
      this.checkPhishTank(url),
      this.checkVirusTotal(url)
    ]);

    const layers: DetectionLayer[] = [];

    results.forEach((result, index) => {
      const apiNames = ['Google Safe Browsing', 'PhishTank', 'VirusTotal'];
      const apiName = apiNames[index];
      
      if (result.status === 'fulfilled' && result.value.success) {
        const response = result.value;
        if (response.malicious) {
          layers.push({
            layer: 'signature',
            method: response.source,
            score: 100, // External API detections are high confidence
            details: `Flagged as malicious by ${response.source}${response.details?.totalDetections ? ` (${response.details.totalDetections} detections)` : ''}`,
            matched: true
          });
        } else {
          // Add clean result for transparency
          layers.push({
            layer: 'signature',
            method: response.source,
            score: 0,
            details: `Checked by ${response.source} - Clean`,
            matched: false
          });
        }
      } else if (result.status === 'fulfilled' && !result.value.success) {
        // Add failed check for transparency
        const response = result.value;
        layers.push({
          layer: 'signature',
          method: apiName,
          score: 0,
          details: `${apiName} check failed: ${response.error || 'Unknown error'}`,
          matched: false
        });
      } else if (result.status === 'rejected') {
        // Add error result for transparency
        layers.push({
          layer: 'signature',
          method: apiName,
          score: 0,
          details: `${apiName} unavailable: ${result.reason}`,
          matched: false
        });
        console.debug(`[LinkShield] API check skipped:`, result.reason);
      }
    });

    return layers;
  }

  /**
   * Rate limiting helper
   */
  private static checkRateLimit(service: string, limit: number): boolean {
    const now = Date.now();
    const counter = this.rateLimitCounters.get(service);

    if (!counter || now > counter.resetTime) {
      // Reset counter
      this.rateLimitCounters.set(service, {
        count: 1,
        resetTime: now + 60000 // 1 minute
      });
      return true;
    }

    if (counter.count >= limit) {
      return false; // Rate limit exceeded
    }

    counter.count++;
    return true;
  }

  /**
   * Clear caches (for testing/debugging)
   */
  public static clearCaches(): void {
    this.safeBrowsingCache.clear();
    this.rateLimitCounters.clear();
  }
}

export default SignatureEngine;
