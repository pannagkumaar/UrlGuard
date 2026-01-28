/**
 * Threat Detection Configuration
 */

export const CONFIG = {
  // API Keys (loaded dynamically from chrome.storage.local)
  // Use getApiKeys() helper to retrieve keys asynchronously
  API_KEYS: {
    GOOGLE_SAFE_BROWSING: 'YOUR_API_KEY_HERE',
    VIRUSTOTAL: 'YOUR_API_KEY_HERE',
    PHISHTANK: 'YOUR_API_KEY_HERE'
  },

  // Cache settings
  CACHE: {
    SAFE_URL_TTL: 3600000, // 1 hour
    MALICIOUS_URL_TTL: 86400000, // 24 hours
    MAX_CACHE_SIZE: 10000
  },

  // Risk thresholds
  RISK_THRESHOLDS: {
    LOW: 25,
    MEDIUM: 40,
    HIGH: 60,
    CRITICAL: 85
  },

  // Heuristic weights
  HEURISTIC_WEIGHTS: {
    IP_URL: 40,
    SUSPICIOUS_TLD: 25,
    PUNYCODE: 35,
    LONG_URL: 15,
    EXCESSIVE_SUBDOMAIN: 20,
    URL_ENCODING: 25,
    SUSPICIOUS_KEYWORDS: 30,
    NO_HTTPS: 15,
    PORT_IN_URL: 20,
    SHORT_DOMAIN: 10
  },

  // Suspicious TLDs (free/cheap domains often abused)
  SUSPICIOUS_TLDS: [
    // Free domains
    'tk', 'ml', 'ga', 'cf', 'gq', 'freenom',
    // Suspicious new gTLDs
    'zip', 'mov', 'loan', 'click', 'work', 'party', 'racing',
    'download', 'stream', 'trade', 'webcam', 'men', 'click',
    // Commonly abused
    'homes', 'top', 'xyz', 'icu', 'site', 'online', 'vip', 'win',
    'bid', 'date', 'faith', 'review', 'science', 'pro', 'cfd',
    'sbs', 'bond', 'live', 'shop', 'club', 'space', 'fun', 'buzz',
    // Additional risky TLDs
    'country', 'kim', 'pw', 'cc', 'ws', 'gdn', 'rest', 'link'
  ],

  // High-risk TLDs (automatic flag)
  HIGH_RISK_TLDS: [
    'tk', 'ml', 'ga', 'cf', 'gq', 'zip', 'mov'
  ],

  // Trusted infrastructure domains (reduce heuristic weight to avoid FPs)
  TRUSTED_INFRA_DOMAINS: [
    // Google services
    'google.com',
    'googleapis.com',
    'googleusercontent.com',
    'gstatic.com',
    'gmail.com',
    'youtube.com',
    'googlevideo.com',
    'google-analytics.com',
    'doubleclick.net',
    // Cloud platforms
    'firebaseapp.com',
    'firebaseio.com',
    'firebasestorage.googleapis.com',
    'appspot.com',
    'cloudfront.net',
    'amazonaws.com',
    'azureedge.net',
    'azure.com',
    // Microsoft services
    'microsoft.com',
    'microsoftonline.com',
    'office.com',
    'outlook.com',
    'live.com',
    'windows.net',
    // Development platforms
    'github.com',
    'github.io',
    'gitlab.com',
    'bitbucket.org',
    'sourceforge.net',
    'npmjs.com',
    'stackoverflow.com',
    // Other major services
    'apple.com',
    'icloud.com',
    'facebook.com',
    'fbcdn.net',
    'twitter.com',
    'twimg.com',
    'linkedin.com',
    'licdn.com',
    'amazon.com',
    'ssl-images-amazon.com',
    'cloudflare.com',
    'akamai.net',
    'fastly.net'
  ],

  // Phishing keywords
  PHISHING_KEYWORDS: [
    'login', 'signin', 'verify', 'account', 'security', 'update',
    'confirm', 'banking', 'paypal', 'suspended', 'limited',
    'unusual', 'activity', 'locked', 'validate', 'secure',
    'password', 'credential', 'verification', 'authorize',
    'authenticate', 'billing', 'payment', 'wallet', 'invoice'
  ],

  // Urgent language patterns (social engineering)
  URGENT_KEYWORDS: [
    'urgent', 'immediate', 'action required', 'expire', 'expires',
    'suspended', 'locked', 'unauthorized', 'verify now', 'click here',
    'act now', 'limited time', 'suspended account'
  ],

  // Brand impersonation targets
  TARGETED_BRANDS: [
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook',
    'netflix', 'instagram', 'twitter', 'linkedin', 'dropbox',
    'bankofamerica', 'chase', 'wellsfargo', 'citibank'
  ],

  // URL length thresholds
  URL_LENGTH: {
    SUSPICIOUS: 75,
    VERY_SUSPICIOUS: 150,
    EXTREME: 250
  },

  // Subdomain thresholds
  MAX_SUBDOMAINS: 4,
  SUSPICIOUS_SUBDOMAIN_COUNT: 3,

  // Path analysis
  PATH_ANALYSIS: {
    MAX_DEPTH: 8, // /a/b/c/d/e/f/g/h/ = 8 levels
    MAX_SLASHES: 10
  },

  // Domain characteristics
  DOMAIN_ANALYSIS: {
    MIN_LENGTH_FOR_ENTROPY: 8,
    SHORT_DOMAIN_THRESHOLD: 4, // very short domains like ab.com
    LONG_DOMAIN_THRESHOLD: 30
  },

  // API rate limiting
  RATE_LIMITS: {
    SAFE_BROWSING_PER_MINUTE: 60,
    VIRUSTOTAL_PER_DAY: 500
  }
};

export default CONFIG;
