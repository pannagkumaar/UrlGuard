/**
 * Test script to demonstrate the new threat analysis priority logic
 * This shows how external APIs (VirusTotal, Google Safe Browsing, PhishTank) 
 * take priority while still showing all detection scores
 */

import { ThreatAnalysisResult, DetectionLayer } from './src/types/types';

// Mock function to simulate the new buildResult logic
function buildResultDemo(url: string, layers: DetectionLayer[]): ThreatAnalysisResult {
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
    if (totalScore >= 75) riskLevel = 'critical';
    else if (totalScore >= 60) riskLevel = 'high';
    else if (totalScore >= 40) riskLevel = 'medium';
    else if (totalScore >= 20) riskLevel = 'low';
    else riskLevel = 'safe';
    
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

// Test Cases
console.log("=== LinkShield Priority Logic Test ===\n");

// Test Case 1: VirusTotal flags it as malicious (should override other scores)
console.log("Test 1: VirusTotal detects malware");
const test1Layers: DetectionLayer[] = [
  {
    layer: 'signature',
    method: 'VirusTotal',
    score: 100,
    details: 'Flagged as malicious by VirusTotal (5 detections)',
    matched: true
  },
  {
    layer: 'signature',
    method: 'Google Safe Browsing',
    score: 0,
    details: 'Checked by Google Safe Browsing - Clean',
    matched: false
  },
  {
    layer: 'heuristic',
    method: 'URL Analysis',
    score: 25,
    details: 'Suspicious URL patterns detected',
    matched: true
  },
  {
    layer: 'ml',
    method: 'ML Model',
    score: 30,
    details: 'Medium risk score from ML analysis',
    matched: true
  }
];

const result1 = buildResultDemo('https://suspicious-site.com', test1Layers);
console.log(`Result: ${result1.isMalicious ? 'MALICIOUS' : 'SAFE'} (Score: ${result1.riskScore}/100, Risk: ${result1.riskLevel})`);
console.log(`Details: ${result1.details}\n`);

// Test Case 2: All external APIs clean, but internal methods detect issues
console.log("Test 2: External APIs clean, internal detection finds issues");
const test2Layers: DetectionLayer[] = [
  {
    layer: 'signature',
    method: 'VirusTotal',
    score: 0,
    details: 'Checked by VirusTotal - Clean',
    matched: false
  },
  {
    layer: 'signature',
    method: 'Google Safe Browsing',
    score: 0,
    details: 'Checked by Google Safe Browsing - Clean',
    matched: false
  },
  {
    layer: 'signature',
    method: 'PhishTank',
    score: 0,
    details: 'Checked by PhishTank - Clean',
    matched: false
  },
  {
    layer: 'heuristic',
    method: 'URL Analysis',
    score: 45,
    details: 'High-risk URL patterns detected',
    matched: true
  },
  {
    layer: 'heuristic',
    method: 'Domain Analysis',
    score: 30,
    details: 'Suspicious domain characteristics',
    matched: true
  },
  {
    layer: 'ml',
    method: 'ML Model',
    score: 35,
    details: 'High risk score from ML analysis',
    matched: true
  }
];

const result2 = buildResultDemo('https://potential-phish.com', test2Layers);
console.log(`Result: ${result2.isMalicious ? 'MALICIOUS' : 'SAFE'} (Score: ${result2.riskScore}/100, Risk: ${result2.riskLevel})`);
console.log(`Details: ${result2.details}\n`);

// Test Case 3: Everything clean
console.log("Test 3: All detection methods report clean");
const test3Layers: DetectionLayer[] = [
  {
    layer: 'signature',
    method: 'VirusTotal',
    score: 0,
    details: 'Checked by VirusTotal - Clean',
    matched: false
  },
  {
    layer: 'signature',
    method: 'Google Safe Browsing',
    score: 0,
    details: 'Checked by Google Safe Browsing - Clean',
    matched: false
  },
  {
    layer: 'heuristic',
    method: 'URL Analysis',
    score: 0,
    details: 'No suspicious patterns detected',
    matched: false
  },
  {
    layer: 'ml',
    method: 'ML Model',
    score: 0,
    details: 'Low risk score from ML analysis',
    matched: false
  }
];

const result3 = buildResultDemo('https://google.com', test3Layers);
console.log(`Result: ${result3.isMalicious ? 'MALICIOUS' : 'SAFE'} (Score: ${result3.riskScore}/100, Risk: ${result3.riskLevel})`);
console.log(`Details: ${result3.details}\n`);

console.log("=== Key Features Demonstrated ===");
console.log("✅ External APIs (VirusTotal, etc.) override internal scoring");
console.log("✅ All detection scores are preserved and shown for transparency");
console.log("✅ Internal methods still provide value when external APIs are clean");
console.log("✅ Clear indication of which method made the final determination");