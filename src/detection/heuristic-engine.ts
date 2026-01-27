/**
 * Layer 2: Heuristic Analysis Engine
 * Analyzes URL patterns and characteristics for suspicious indicators
 */

import { CONFIG } from '../config/config';
import { URLFeatures, DetectionLayer } from '../types/types';
// @ts-ignore
import * as punycode from 'punycode/';

export class HeuristicEngine {
  /**
   * Extract features from URL
   */
  public static extractFeatures(url: string): URLFeatures {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname;
      const pathname = urlObj.pathname;

      // Count subdomains
      const domainParts = hostname.split('.');
      const subdomainCount = Math.max(0, domainParts.length - 2);

      // Check for IP address
      const hasIP = HeuristicEngine.isIPAddress(hostname);

      // Check for punycode (IDN homograph attack)
      const hasPunycode = hostname.includes('xn--');

      // Check for suspicious TLD
      const tld = domainParts[domainParts.length - 1];
      const hasSuspiciousTLD = CONFIG.SUSPICIOUS_TLDS.includes(tld.toLowerCase());

      // Check for port
      const hasPort = urlObj.port !== '';

      // Count special characters
      const specialCharCount = (url.match(/[^a-zA-Z0-9]/g) || []).length;
      const digitCount = (url.match(/\d/g) || []).length;

      // Calculate entropy
      const entropy = HeuristicEngine.calculateEntropy(hostname);

      // Smart URL encoding detection - check WHERE encoding occurs
      const urlEncodingCount = (url.match(/%[0-9A-F]{2}/gi) || []).length;
      const hostnameEncodingCount = (hostname.match(/%[0-9A-F]{2}/gi) || []).length;
      const pathEncodingCount = (pathname.match(/%[0-9A-F]{2}/gi) || []).length;
      const queryEncodingCount = (urlObj.search.match(/%[0-9A-F]{2}/gi) || []).length;
      
      // Encoding in hostname is very suspicious, in query params is normal
      const suspiciousEncoding = hostnameEncodingCount > 0 || pathEncodingCount > 5;

      // Count phishing keywords
      const urlLower = url.toLowerCase();
      const phishingKeywordCount = CONFIG.PHISHING_KEYWORDS.filter(
        keyword => urlLower.includes(keyword)
      ).length;

      // Count urgent keywords (social engineering)
      const urgentKeywordCount = CONFIG.URGENT_KEYWORDS.filter(
        keyword => urlLower.includes(keyword)
      ).length;

      // Path analysis
      const pathDepth = pathname.split('/').filter(p => p.length > 0).length;
      const pathSlashCount = (pathname.match(/\//g) || []).length;

      // Consecutive character patterns (e.g., "aaa", "111")
      const hasConsecutiveChars = /([a-z0-9])\1{3,}/i.test(hostname);

      // Check for URL shortener domains
      const isShortener = HeuristicEngine.isURLShortener(hostname);

      // Detect suspicious character patterns
      const hasHyphenSpam = (hostname.match(/-/g) || []).length > 3;
      const hasDotSpam = domainParts.length > 5;

      // Check for brand impersonation
      const brandImpersonation = HeuristicEngine.detectBrandImpersonation(hostname);

      // URL quality analysis - legitimate services have readable param names
      const queryParams = urlObj.search;
      const hasReadableParams = queryParams.length > 0 && /[a-z]{3,}=[^&]+/i.test(queryParams);
      const hasRandomParams = queryParams.length > 0 && /[a-z0-9]{20,}/i.test(queryParams);
      
      // Known legitimate domain pattern (second-level domain quality)
      const sld = domainParts.length >= 2 ? domainParts[domainParts.length - 2] : '';
      const hasQualityDomain = sld.length >= 3 && /^[a-z]+$/i.test(sld) && !(/[0-9]/.test(sld));

      return {
        length: url.length,
        domainLength: hostname.length,
        subdomainCount,
        hasIP,
        usesHTTPS: urlObj.protocol === 'https:',
        hasSuspiciousTLD,
        hasPunycode,
        hasPort,
        specialCharCount,
        digitCount,
        entropy,
        urlEncodingCount,
        suspiciousEncoding, // NEW: context-aware encoding
        hasReadableParams, // NEW: legitimate URL structure
        hasRandomParams, // NEW: obfuscation detection
        hasQualityDomain, // NEW: domain reputation signal
        phishingKeywordCount,
        urgentKeywordCount,
        brandImpersonation,
        pathDepth,
        pathSlashCount,
        hasConsecutiveChars,
        isShortener,
        hasHyphenSpam,
        hasDotSpam
      };
    } catch (error) {
      console.error('Error extracting features:', error);
      // Return safe defaults on error
      return {
        length: 0,
        domainLength: 0,
        subdomainCount: 0,
        hasIP: false,
        usesHTTPS: true,
        hasSuspiciousTLD: false,
        hasPunycode: false,
        hasPort: false,
        specialCharCount: 0,
        digitCount: 0,
        entropy: 0,
        urlEncodingCount: 0,
        suspiciousEncoding: false,
        hasReadableParams: true,
        hasRandomParams: false,
        hasQualityDomain: true,
        phishingKeywordCount: 0,
        urgentKeywordCount: 0,
        brandImpersonation: null,
        pathDepth: 0,
        pathSlashCount: 0,
        hasConsecutiveChars: false,
        isShortener: false,
        hasHyphenSpam: false,
        hasDotSpam: false
      };
    }
  }

  /**
   * Analyze URL using heuristics and return detection layers
   */
  public static analyze(url: string): DetectionLayer[] {
    const features = this.extractFeatures(url);
    const layers: DetectionLayer[] = [];
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    const isTrustedInfra = CONFIG.TRUSTED_INFRA_DOMAINS.some(domain =>
      hostname === domain || hostname.endsWith(`.${domain}`)
    );

    // Check for IP-based URL
    if (features.hasIP) {
      layers.push({
        layer: 'heuristic',
        method: 'IP Address Detection',
        score: CONFIG.HEURISTIC_WEIGHTS.IP_URL,
        details: 'URL uses IP address instead of domain name',
        matched: true
      });
    }

    // Check for suspicious TLD
    if (features.hasSuspiciousTLD) {
      layers.push({
        layer: 'heuristic',
        method: 'Suspicious TLD',
        score: CONFIG.HEURISTIC_WEIGHTS.SUSPICIOUS_TLD,
        details: 'Domain uses a TLD commonly associated with phishing',
        matched: true
      });
    }

    // Check for punycode (homograph attack)
    if (features.hasPunycode) {
      layers.push({
        layer: 'heuristic',
        method: 'Punycode/IDN Detection',
        score: CONFIG.HEURISTIC_WEIGHTS.PUNYCODE,
        details: 'URL contains internationalized domain (potential homograph attack)',
        matched: true
      });
    }

    // Check for long URL (but consider if it's a quality structured URL)
    const isStructuredURL = features.hasReadableParams && features.hasQualityDomain;
    const lengthThreshold = isStructuredURL ? CONFIG.URL_LENGTH.EXTREME : CONFIG.URL_LENGTH.VERY_SUSPICIOUS;
    
    if (!isTrustedInfra && features.length > lengthThreshold) {
      layers.push({
        layer: 'heuristic',
        method: 'Excessive URL Length',
        score: CONFIG.HEURISTIC_WEIGHTS.LONG_URL * 2,
        details: `URL length (${features.length}) is extremely suspicious`,
        matched: true
      });
    } else if (!isTrustedInfra && features.length > CONFIG.URL_LENGTH.SUSPICIOUS && !isStructuredURL) {
      layers.push({
        layer: 'heuristic',
        method: 'Long URL',
        score: CONFIG.HEURISTIC_WEIGHTS.LONG_URL,
        details: `URL length (${features.length}) is suspicious`,
        matched: true
      });
    }

    // Check for excessive subdomains
    if (features.subdomainCount > CONFIG.MAX_SUBDOMAINS) {
      layers.push({
        layer: 'heuristic',
        method: 'Excessive Subdomains',
        score: CONFIG.HEURISTIC_WEIGHTS.EXCESSIVE_SUBDOMAIN,
        details: `URL has ${features.subdomainCount} subdomains (suspicious)`,
        matched: true
      });
    }

    // Check for URL encoding abuse (context-aware)
    // Encoding in hostname is highly suspicious, lots in query params is normal for APIs
    if (features.suspiciousEncoding) {
      layers.push({
        layer: 'heuristic',
        method: 'Suspicious URL Encoding',
        score: CONFIG.HEURISTIC_WEIGHTS.URL_ENCODING,
        details: 'URL encoding found in hostname or excessive in path (obfuscation attempt)',
        matched: true
      });
    }

    // Check for phishing keywords
    // Re-evaluate phishing keywords: if on trusted infra, only count keywords appearing in hostname
    const hostnameLower = hostname;
    const urlLower = url.toLowerCase();
    const keywordCountHostOnly = CONFIG.PHISHING_KEYWORDS.filter(
      keyword => hostnameLower.includes(keyword)
    ).length;

    const phishingCount = isTrustedInfra ? keywordCountHostOnly : features.phishingKeywordCount;

    if (phishingCount > 0) {
      layers.push({
        layer: 'heuristic',
        method: 'Phishing Keywords',
        score: CONFIG.HEURISTIC_WEIGHTS.SUSPICIOUS_KEYWORDS * phishingCount,
        details: `Contains ${phishingCount} phishing-related keyword(s)${isTrustedInfra ? ' in hostname' : ''}`,
        matched: true
      });
    }

    // Check for brand impersonation
    if (features.brandImpersonation) {
      layers.push({
        layer: 'heuristic',
        method: 'Brand Impersonation',
        score: 50,
        details: `Potential impersonation of ${features.brandImpersonation}`,
        matched: true
      });
    }

    // Check for missing HTTPS
    if (!features.usesHTTPS && features.phishingKeywordCount > 0) {
      layers.push({
        layer: 'heuristic',
        method: 'No HTTPS on Sensitive Page',
        score: CONFIG.HEURISTIC_WEIGHTS.NO_HTTPS,
        details: 'Sensitive page without HTTPS encryption',
        matched: true
      });
    }

      // Check for consecutive character spam
      if (features.hasConsecutiveChars) {
        layers.push({
          layer: 'heuristic',
          method: 'Character Pattern Anomaly',
          score: 15,
          details: 'Domain contains suspicious repeated character patterns',
          matched: true
        });
      }

      // Check for URL shortener (medium risk)
      if (features.isShortener) {
        layers.push({
          layer: 'heuristic',
          method: 'URL Shortener Detected',
          score: 10,
          details: 'URL uses a shortening service (destination unknown)',
          matched: true
        });
      }

      // Check for hyphen/dot spam
      if (features.hasHyphenSpam) {
        layers.push({
          layer: 'heuristic',
          method: 'Hyphen Spam',
          score: 18,
          details: 'Domain contains excessive hyphens',
          matched: true
        });
      }

      if (features.hasDotSpam) {
        layers.push({
          layer: 'heuristic',
          method: 'Subdomain Spam',
          score: 20,
          details: 'Domain has excessive subdomain levels',
          matched: true
        });
      }

      // Check for deep path nesting
      if (features.pathDepth > CONFIG.PATH_ANALYSIS.MAX_DEPTH) {
        layers.push({
          layer: 'heuristic',
          method: 'Excessive Path Depth',
          score: 12,
          details: `Path has ${features.pathDepth} levels (suspicious structure)`,
          matched: true
        });
      }

      // Check for urgent language (social engineering)
      if (features.urgentKeywordCount > 0) {
        layers.push({
          layer: 'heuristic',
          method: 'Social Engineering Language',
          score: 25 * features.urgentKeywordCount,
          details: `Contains ${features.urgentKeywordCount} urgent/pressure keyword(s)`,
          matched: true
        });
      }

      // Check for high entropy domain/subdomain (skip for trusted infra to reduce FPs)
      if (!isTrustedInfra && features.entropy > 4.0) {
        layers.push({
          layer: 'heuristic',
          method: 'High Domain Entropy',
          score: 25,
          details: `Domain has high entropy (${features.entropy.toFixed(2)}), possibly randomly generated`,
          matched: true
        });
      }

      // Re-extract domain parts for analysis
      const domainParts = urlObj.hostname.split('.');
      
      // Analyze SLD (Second Level Domain) and Subdomains
      // e.g. in "sub.example.com", SLD is "example", subdomain is "sub"
      // in "029ajjkz-05958z.cfd", SLD is "029ajjkz-05958z"
      
      if (domainParts.length >= 2) {
        // Get the part before the TLD
        const sld = domainParts[domainParts.length - 2];
        const isSuspiciousSLD = 
           // Pattern 1: Long alphanumeric with hyphen (common in DGA)
           (/[a-z0-9]+-[a-z0-9]+/.test(sld) && /[0-9]/.test(sld) && sld.length > 12) ||
           // Pattern 2: High density of random numbers/chars
           (/[a-z]{5,}[0-9]{3,}/.test(sld)) ||
           // Pattern 3: Random hex-like string > 8 chars
           (/^[a-f0-9]{10,}$/i.test(sld));

        if (isSuspiciousSLD) {
             layers.push({
              layer: 'heuristic',
              method: 'DGA / Random Domain',
              score: 35,
              details: 'Domain name pattern appears randomly generated or algorithmic',
              matched: true
            });
        }
      }

      // Check for suspicious subdomain patterns if they exist
      if (domainParts.length > 2) {
        const subdomain = domainParts[0];
        // Matches short hex-like or random alphanumeric strings
        if (/^[a-f0-9]{3,8}$/i.test(subdomain) || (subdomain.length > 5 && /\d/.test(subdomain) && /[a-z]/.test(subdomain))) {
           layers.push({
            layer: 'heuristic',
            method: 'Suspicious Subdomain',
            score: 30,
            details: 'Subdomain appears to be a generated hash or ID',
            matched: true
          });
        }
      }

      return layers;
    }

  /**
   * Check if hostname is a URL shortener
   */
  private static isURLShortener(hostname: string): boolean {
    const shorteners = [
      'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
      'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'short.link',
      'cutt.ly', 'rb.gy', 'tiny.cc', 'bc.vc'
    ];
    return shorteners.some(s => hostname === s || hostname.endsWith(`.${s}`));
  }

  /**
   * Check if hostname is an IP address
   */
  private static isIPAddress(hostname: string): boolean {
    // IPv4
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Pattern.test(hostname)) {
      return true;
    }

    // IPv6
    const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
    if (ipv6Pattern.test(hostname)) {
      return true;
    }

    return false;
  }

  /**
   * Calculate Shannon entropy of a string
   */
  private static calculateEntropy(str: string): number {
    const len = str.length;
    const frequencies: { [key: string]: number } = {};

    for (let i = 0; i < len; i++) {
      const char = str[i];
      frequencies[char] = (frequencies[char] || 0) + 1;
    }

    let entropy = 0;
    for (const char in frequencies) {
      const p = frequencies[char] / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  /**
   * Detect brand impersonation attempts
   */
  private static detectBrandImpersonation(hostname: string): string | null {
    const hostLower = hostname.toLowerCase();

    for (const brand of CONFIG.TARGETED_BRANDS) {
      // Check for brand name in domain but not official
      if (hostLower.includes(brand) && !hostLower.endsWith(`${brand}.com`)) {
        return brand;
      }

      // Check for typosquatting (e.g., "paypa1" instead of "paypal")
      const distance = HeuristicEngine.levenshteinDistance(hostLower, `${brand}.com`);
      if (distance > 0 && distance <= 2 && hostLower.includes(brand.substring(0, 4))) {
        return brand;
      }

      // Check for lookalike characters (homograph)
      const lookalikes: { [key: string]: string[] } = {
        'a': ['а', 'à', 'á', 'â', 'ã', 'ä'],
        'e': ['е', 'è', 'é', 'ê', 'ë'],
        'i': ['і', 'ì', 'í', 'î', 'ï'],
        'o': ['о', 'ò', 'ó', 'ô', 'õ', 'ö', '0'],
        'l': ['1', 'і', '|']
      };

      for (const [normal, fakes] of Object.entries(lookalikes)) {
        for (const fake of fakes) {
          if (hostLower.includes(fake) && brand.includes(normal)) {
            return brand;
          }
        }
      }
    }

    return null;
  }

  /**
   * Calculate Levenshtein distance (edit distance) between two strings
   */
  private static levenshteinDistance(a: string, b: string): number {
    const matrix: number[][] = [];

    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }

    return matrix[b.length][a.length];
  }

  /**
   * Calculate overall heuristic score
   */
  public static calculateScore(layers: DetectionLayer[]): number {
    const totalScore = layers.reduce((sum, layer) => sum + layer.score, 0);
    return Math.min(100, totalScore); // Cap at 100
  }
}

export default HeuristicEngine;
