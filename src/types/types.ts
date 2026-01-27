/**
 * Type Definitions for LinkShield
 */

export interface ThreatAnalysisResult {
  url: string;
  isMalicious: boolean;
  riskScore: number; // 0-100
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  detectionLayers: DetectionLayer[];
  timestamp: number;
  details: string;
}

export interface DetectionLayer {
  layer: 'signature' | 'heuristic' | 'ml' | 'behavior';
  method: string;
  score: number;
  details: string;
  matched: boolean;
}

export interface URLFeatures {
  length: number;
  domainLength: number;
  subdomainCount: number;
  hasIP: boolean;
  usesHTTPS: boolean;
  hasSuspiciousTLD: boolean;
  hasPunycode: boolean;
  hasPort: boolean;
  specialCharCount: number;
  digitCount: number;
  entropy: number;
  urlEncodingCount: number;
  suspiciousEncoding: boolean; // NEW: encoding in wrong places
  hasReadableParams: boolean; // NEW: structured URL quality
  hasRandomParams: boolean; // NEW: obfuscation detection
  hasQualityDomain: boolean; // NEW: domain reputation
  phishingKeywordCount: number;
  urgentKeywordCount: number;
  brandImpersonation: string | null;
  pathDepth: number;
  pathSlashCount: number;
  hasConsecutiveChars: boolean;
  isShortener: boolean;
  hasHyphenSpam: boolean;
  hasDotSpam: boolean;
}

export interface CacheEntry {
  result: ThreatAnalysisResult;
  timestamp: number;
}

export interface Statistics {
  totalChecked: number;
  totalBlocked: number;
  blockedByLayer: {
    signature: number;
    heuristic: number;
    ml: number;
    behavior: number;
  };
  riskDistribution: {
    safe: number;
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  lastReset: number;
}

export interface BlockedSite {
  url: string;
  timestamp: number;
  riskLevel: string;
  reason: string;
}

export interface WhitelistEntry {
  domain: string;
  addedDate: number;
  reason?: string;
}

export interface APIResponse {
  success: boolean;
  malicious: boolean;
  source: string;
  details?: any;
  error?: string;
}

export interface MLFeatureVector {
  urlLength: number;
  domainLength: number;
  pathLength: number;
  queryLength: number;
  subdomainCount: number;
  digitRatio: number;
  specialCharRatio: number;
  consonantRatio: number;
  entropy: number;
  hasIP: number; // 0 or 1
  usesHTTPS: number; // 0 or 1
  hasSuspiciousTLD: number; // 0 or 1
  hasPunycode: number; // 0 or 1
  phishingKeywordScore: number;
  urgentKeywordScore: number;
  pathDepth: number;
  hasConsecutiveChars: number; // 0 or 1
  isShortener: number; // 0 or 1
  // NEW: Quality signals
  hasReadableParams: number; // 0 or 1
  hasQualityDomain: number; // 0 or 1
  // NEW: Suspicious signals
  suspiciousEncoding: number; // 0 or 1
  hasRandomParams: number; // 0 or 1
}
