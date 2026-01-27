/**
 * Layer 3: ML-Based Detection
 * Feature extraction and scoring for machine learning model
 */

import { MLFeatureVector, URLFeatures } from '../types/types';
import { HeuristicEngine } from './heuristic-engine';

export class MLEngine {
  /**
   * Convert URL features to ML feature vector
   */
  public static extractMLFeatures(url: string): MLFeatureVector {
    const features = HeuristicEngine.extractFeatures(url);

    try {
      const urlObj = new URL(url);
      const pathLength = urlObj.pathname.length;
      const queryLength = urlObj.search.length;

      // Advanced ratios
      const digitRatio = features.digitCount / Math.max(features.length, 1);
      const specialCharRatio = features.specialCharCount / Math.max(features.length, 1);
      const vowelCount = (url.match(/[aeiou]/gi) || []).length;
      const consonantRatio = (features.length - vowelCount - features.digitCount) / Math.max(features.length, 1);

      return {
        urlLength: features.length,
        domainLength: features.domainLength,
        pathLength,
        queryLength,
        subdomainCount: features.subdomainCount,
        digitRatio,
        specialCharRatio,
        consonantRatio,
        entropy: features.entropy,
        hasIP: features.hasIP ? 1 : 0,
        usesHTTPS: features.usesHTTPS ? 1 : 0,
        hasSuspiciousTLD: features.hasSuspiciousTLD ? 1 : 0,
        hasPunycode: features.hasPunycode ? 1 : 0,
        phishingKeywordScore: features.phishingKeywordCount * 10,
        urgentKeywordScore: features.urgentKeywordCount * 15,
        pathDepth: features.pathDepth,
        hasConsecutiveChars: features.hasConsecutiveChars ? 1 : 0,
        isShortener: features.isShortener ? 1 : 0,
        // NEW: Quality signals (positive indicators)
        hasReadableParams: features.hasReadableParams ? 1 : 0,
        hasQualityDomain: features.hasQualityDomain ? 1 : 0,
        // NEW: Suspicious signals (negative indicators)
        suspiciousEncoding: features.suspiciousEncoding ? 1 : 0,
        hasRandomParams: features.hasRandomParams ? 1 : 0
      };
    } catch (error) {
      console.error('Error extracting ML features:', error);
      return {
        urlLength: 0,
        domainLength: 0,
        pathLength: 0,
        queryLength: 0,
        subdomainCount: 0,
        digitRatio: 0,
        specialCharRatio: 0,
        consonantRatio: 0,
        entropy: 0,
        hasIP: 0,
        usesHTTPS: 1,
        hasSuspiciousTLD: 0,
        hasPunycode: 0,
        phishingKeywordScore: 0,
        urgentKeywordScore: 0,
        pathDepth: 0,
        hasConsecutiveChars: 0,
        isShortener: 0,
        hasReadableParams: 1,
        hasQualityDomain: 1,
        suspiciousEncoding: 0,
        hasRandomParams: 0
      };
    }
  }

  /**
   * Enhanced ML scoring with confidence metrics and quality awareness
   * In production, this would be replaced with a trained model (ONNX, TensorFlow.js)
   */
  public static predict(features: MLFeatureVector): { score: number; confidence: number } {
    let score = 0;
    let confidence = 0.7; // Base confidence

    // POSITIVE SIGNALS (legitimacy indicators - reduce score)
    let legitimacyBonus = 0;
    
    if (features.hasReadableParams === 1) {
      legitimacyBonus += 20; // Readable params = legitimate API structure
      confidence += 0.08;
    }
    
    if (features.hasQualityDomain === 1) {
      legitimacyBonus += 15; // Quality domain name = established service
      confidence += 0.05;
    }
    
    if (features.usesHTTPS === 1 && features.hasQualityDomain === 1) {
      legitimacyBonus += 8; // HTTPS + quality domain = strong legitimacy signal
    }

    // NEGATIVE SIGNALS (suspicious indicators - increase score)
    // Critical indicators (high weight)
    if (features.hasIP) {
      score += 35;
      confidence += 0.15;
    }
    if (features.hasPunycode) {
      score += 30;
      confidence += 0.1;
    }
    if (features.hasSuspiciousTLD) {
      score += 28;
      confidence += 0.08;
    }
    
    // Context-aware encoding (suspicious encoding in hostname/path)
    if (features.suspiciousEncoding === 1) {
      score += 30;
      confidence += 0.1;
    }
    
    // Random/obfuscated parameters (vs readable ones)
    if (features.hasRandomParams === 1) {
      score += 22;
      confidence += 0.08;
    }

    // URL length (more lenient if structured)
    const lengthPenalty = features.hasReadableParams === 1 ? 0.5 : 1.0;
    if (features.urlLength > 300) {
      score += Math.floor(25 * lengthPenalty);
    } else if (features.urlLength > 200) {
      score += Math.floor(15 * lengthPenalty);
    } else if (features.urlLength > 120) {
      score += Math.floor(8 * lengthPenalty);
    }

    // Domain characteristics
    if (features.domainLength > 40) {
      score += 18;
    } else if (features.domainLength > 25) {
      score += 10;
    }

    // Subdomain analysis
    if (features.subdomainCount > 5) {
      score += 30;
      confidence += 0.1;
    } else if (features.subdomainCount > 3) {
      score += 18;
    } else if (features.subdomainCount > 2) {
      score += 10;
    }

    // Path depth
    if (features.pathDepth > 10) {
      score += 15;
    } else if (features.pathDepth > 7) {
      score += 8;
    }

    // Character composition
    if (features.digitRatio > 0.4) {
      score += 20;
      confidence += 0.05;
    } else if (features.digitRatio > 0.25) {
      score += 12;
    }

    if (features.specialCharRatio > 0.35) {
      score += 18;
    } else if (features.specialCharRatio > 0.2) {
      score += 10;
    }

    // Consonant clustering
    if (features.consonantRatio > 0.7) {
      score += 12;
    }

    // Entropy (randomness)
    if (features.entropy > 4.8) {
      score += 25;
      confidence += 0.1;
    } else if (features.entropy > 4.2) {
      score += 15;
    } else if (features.entropy > 3.8) {
      score += 8;
    }

    // Pattern anomalies
    if (features.hasConsecutiveChars) {
      score += 12;
    }

    // Social engineering
    score += Math.min(features.phishingKeywordScore, 35);
    score += Math.min(features.urgentKeywordScore, 40);
    
    if (features.urgentKeywordScore > 20) {
      confidence += 0.15;
    }

    // URL shortener
    if (features.isShortener) {
      score += 12;
      confidence -= 0.1;
    }

    // HTTPS (minor factor)
    if (!features.usesHTTPS) {
      score += 10;
    }

    // Apply legitimacy bonus
    score = Math.max(0, score - legitimacyBonus);
    
    // Normalize
    score = Math.min(100, Math.max(0, score));
    confidence = Math.min(1.0, Math.max(0.1, confidence));

    return { score, confidence };
  }

  /**
   * Get ML-based detection layer
   */
  public static analyze(url: string) {
    const features = this.extractMLFeatures(url);
    const prediction = this.predict(features);
    const score = prediction.score;
    const confidence = prediction.confidence;

    return {
      layer: 'ml' as const,
      method: `ML Model (${(confidence * 100).toFixed(0)}% confidence)`,
      score,
      details: `ML prediction: ${score}/100 (confidence: ${(confidence * 100).toFixed(0)}%)`,
      matched: score > 45, // Lower threshold for ML with confidence
      features,
      confidence
    };
  }

  /**
   * Export feature vector for model training (useful for collecting training data)
   */
  public static exportFeatures(url: string, label: boolean): string {
    const features = this.extractMLFeatures(url);
    return JSON.stringify({ url, label, features, timestamp: Date.now() });
  }
}

export default MLEngine;
