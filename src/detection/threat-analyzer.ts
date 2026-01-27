/**
 * Main Threat Analyzer
 * Orchestrates all detection layers and produces final verdict
 * 
 * Priority Logic:
 * 1. External APIs (VirusTotal, Google Safe Browsing, PhishTank) are the source of truth
 * 2. If ANY external API flags a URL as malicious, it's considered malicious
 * 3. All detection layers still run for transparency and complete scoring
 * 4. Internal detection methods (heuristics, ML) are used when external APIs are clean
 */

import { ThreatAnalysisResult, DetectionLayer, CacheEntry } from '../types/types';
import { CONFIG } from '../config/config';
import { HeuristicEngine } from './heuristic-engine';
import { SignatureEngine } from './signature-engine';
import { MLEngine } from './ml-engine';

export class ThreatAnalyzer {
  private static cache = new Map<string, CacheEntry>();
  private static whitelist = new Set<string>();

  /**
   * Main analysis function - runs all detection layers
   */
  public static async analyze(url: string): Promise<ThreatAnalysisResult> {
    try {
      // Normalize URL
      const normalizedUrl = this.normalizeURL(url);

      // Check whitelist
      const hostname = new URL(normalizedUrl).hostname;
      if (this.whitelist.has(hostname)) {
        return {
          url: normalizedUrl,
          isMalicious: false,
          riskScore: 0,
          riskLevel: 'safe',
          detectionLayers: [{
            layer: 'signature',
            method: 'Whitelist',
            score: 0,
            details: 'Domain is whitelisted',
            matched: false
          }],
          timestamp: Date.now(),
          details: 'Whitelisted domain'
        };
      }

      // Check cache
      const cached = this.cache.get(normalizedUrl);
      if (cached && Date.now() - cached.timestamp < CONFIG.CACHE.SAFE_URL_TTL) {
        return cached.result;
      }

      // Run all detection layers
      const allLayers: DetectionLayer[] = [];

      // Layer 1: Signature-based (API checks)
      const signatureLayers = await SignatureEngine.checkAllAPIs(normalizedUrl);
      allLayers.push(...signatureLayers);

      // Layer 2: Heuristic analysis (always run for complete analysis)
      const heuristicLayers = HeuristicEngine.analyze(normalizedUrl);
      allLayers.push(...heuristicLayers);

      // Layer 3: ML-based detection (always run for complete analysis)
      const mlLayer = MLEngine.analyze(normalizedUrl);
      allLayers.push(mlLayer);
      
      // Note: We no longer return early on signature matches to allow
      // all detection methods to contribute scores for transparency

      // Build final result
      const result = this.buildResult(normalizedUrl, allLayers);
      this.cacheResult(normalizedUrl, result);

      return result;
    } catch (error) {
      console.error('Error analyzing URL:', error);
      
      // Return safe verdict on error (fail-open to avoid breaking browsing)
      return {
        url,
        isMalicious: false,
        riskScore: 0,
        riskLevel: 'safe',
        detectionLayers: [{
          layer: 'signature',
          method: 'Error Handler',
          score: 0,
          details: `Analysis error: ${error instanceof Error ? error.message : 'Unknown'}`,
          matched: false
        }],
        timestamp: Date.now(),
        details: 'Error during analysis'
      };
    }
  }

  /**
   * Build final threat analysis result
   */
  private static buildResult(url: string, layers: DetectionLayer[]): ThreatAnalysisResult {
    // Separate external API results from other detection methods
    const externalAPILayers = layers.filter(l => 
      l.layer === 'signature' && 
      (l.method.includes('VirusTotal') || 
       l.method.includes('Google Safe Browsing') || 
       l.method.includes('PhishTank'))
    );
    
    const otherLayers = layers.filter(l => !externalAPILayers.includes(l));
    
    // Check if any external API flagged it as malicious
    const externalAPIDetected = externalAPILayers.some(l => l.matched);
    
    let totalScore = 0;
    let isMalicious = false;
    let riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical' = 'safe';
    let details = '';
    
    if (externalAPIDetected) {
      // External APIs are the source of truth - treat as malicious
      totalScore = 100;
      isMalicious = true;
      riskLevel = 'critical';
      
      const matchedAPIs = externalAPILayers.filter(l => l.matched);
      details = `Flagged by external threat intelligence: ${matchedAPIs.map(l => l.method).join(', ')}`;
      
      // Add additional context from other detection methods
      const otherMatched = otherLayers.filter(l => l.matched);
      if (otherMatched.length > 0) {
        details += ` | Also detected by: ${otherMatched.map(l => l.method).join(', ')}`;
      }
    } else {
      // No external API detection - use traditional scoring
      for (const layer of layers) {
        if (layer.matched) {
          totalScore += layer.score;
        }
      }
      
      // Cap at 100
      totalScore = Math.min(100, totalScore);
      
      // Determine risk level using traditional thresholds
      riskLevel = this.getRiskLevel(totalScore);
      isMalicious = riskLevel === 'high' || riskLevel === 'critical';
      
      // Generate details
      const matchedLayers = layers.filter(l => l.matched);
      details = matchedLayers.length > 0
        ? `Detected by: ${matchedLayers.map(l => l.method).join(', ')}`
        : 'No threats detected';
      
      // Add note that external APIs didn't flag it
      if (externalAPILayers.length > 0) {
        details += ' | External threat intelligence: Clean';
      }
    }

    return {
      url,
      isMalicious,
      riskScore: totalScore,
      riskLevel,
      detectionLayers: layers,
      timestamp: Date.now(),
      details
    };
  }

  /**
   * Determine risk level from score
   */
  private static getRiskLevel(score: number): 'safe' | 'low' | 'medium' | 'high' | 'critical' {
    if (score >= CONFIG.RISK_THRESHOLDS.CRITICAL) return 'critical';
    if (score >= CONFIG.RISK_THRESHOLDS.HIGH) return 'high';
    if (score >= CONFIG.RISK_THRESHOLDS.MEDIUM) return 'medium';
    if (score >= CONFIG.RISK_THRESHOLDS.LOW) return 'low';
    return 'safe';
  }

  /**
   * Normalize URL for consistent caching
   */
  private static normalizeURL(url: string): string {
    try {
      const urlObj = new URL(url);
      // Remove fragments and trailing slashes
      urlObj.hash = '';
      let normalized = urlObj.href;
      if (normalized.endsWith('/')) {
        normalized = normalized.slice(0, -1);
      }
      return normalized.toLowerCase();
    } catch {
      return url.toLowerCase();
    }
  }

  /**
   * Cache analysis result
   */
  private static cacheResult(url: string, result: ThreatAnalysisResult): void {
    // Limit cache size
    if (this.cache.size >= CONFIG.CACHE.MAX_CACHE_SIZE) {
      // Remove oldest entries
      const entries = Array.from(this.cache.entries());
      entries.sort((a, b) => a[1].timestamp - b[1].timestamp);
      const toRemove = entries.slice(0, Math.floor(CONFIG.CACHE.MAX_CACHE_SIZE * 0.2));
      toRemove.forEach(([key]) => this.cache.delete(key));
    }

    this.cache.set(url, {
      result,
      timestamp: Date.now()
    });
  }

  /**
   * Add domain to whitelist
   */
  public static addToWhitelist(domain: string): void {
    this.whitelist.add(domain.toLowerCase());
  }

  /**
   * Remove domain from whitelist
   */
  public static removeFromWhitelist(domain: string): void {
    this.whitelist.delete(domain.toLowerCase());
  }

  /**
   * Get whitelist
   */
  public static getWhitelist(): string[] {
    return Array.from(this.whitelist);
  }

  /**
   * Clear cache
   */
  public static clearCache(): void {
    this.cache.clear();
  }
}

export default ThreatAnalyzer;
