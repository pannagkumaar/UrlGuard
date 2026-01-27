# LinkShield Extension - Development Guide

## Quick Start

### Installation
```bash
npm install
```

### Development
```bash
npm run dev
```
This starts webpack in watch mode. Changes will be automatically rebuilt.

### Production Build
```bash
npm run build
```

### Loading Extension

**Chrome/Edge:**
1. Open `chrome://extensions/`
2. Enable "Developer mode" (top right)
3. Click "Load unpacked"
4. Select the `dist/` folder

**Firefox:**
1. Open `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on"
3. Select `dist/manifest.json`

## API Key Setup

### Google Safe Browsing API
1. Go to https://console.cloud.google.com/
2. Create a new project
3. Enable "Safe Browsing API"
4. Create credentials (API key)
5. Add to `src/config/config.ts`

### VirusTotal API
1. Sign up at https://www.virustotal.com/gui/join-us
2. Get your API key from account settings
3. Add to `src/config/config.ts`

### PhishTank API
1. Register at https://www.phishtank.com/register.php
2. Request API access
3. Add to `src/config/config.ts`

**Note:** Extension works without API keys using local heuristics and blacklist.

## Testing

### Manual Testing

1. **Test Safe URL:**
   - Navigate to `https://google.com`
   - Badge should show green checkmark
   - Popup should show "SAFE" status

2. **Test IP-based URL:**
   - Navigate to `http://192.168.1.1`
   - Should trigger heuristic detection
   - May show warning or block depending on other factors

3. **Test Long URL with Keywords:**
   - Try: `http://verify-your-paypal-account-security-update-login.example.com/confirm`
   - Should trigger multiple heuristics
   - Likely to be blocked

4. **Test Form Warnings:**
   - Visit any HTTP site with a login form
   - Content script should highlight form in red

5. **Test Whitelist:**
   - Block a test site
   - Add domain to whitelist via popup
   - Revisit - should now be allowed

### Debugging

**Background Service Worker:**
1. Go to `chrome://extensions/`
2. Click "Service worker" under LinkShield
3. Opens DevTools for background script

**Content Script:**
1. Open DevTools on any webpage
2. Check Console for `[LinkShield]` messages

**Popup:**
1. Right-click extension icon
2. Select "Inspect popup"

## Architecture Overview

### Data Flow

```
User navigates to URL
    ↓
webRequest.onBeforeRequest (Background)
    ↓
ThreatAnalyzer.analyze()
    ├── SignatureEngine.checkAllAPIs()
    ├── HeuristicEngine.analyze()
    └── MLEngine.analyze()
    ↓
Calculate risk score
    ↓
If malicious: Redirect to blocked.html
If safe: Allow navigation + Update badge
    ↓
Store analysis in chrome.storage.session
    ↓
Popup displays statistics
```

### Key Components

**ThreatAnalyzer** (`src/detection/threat-analyzer.ts`)
- Main orchestrator
- Combines all detection layers
- Manages caching and whitelist

**SignatureEngine** (`src/detection/signature-engine.ts`)
- API integrations
- Rate limiting
- Response caching

**HeuristicEngine** (`src/detection/heuristic-engine.ts`)
- Feature extraction
- Pattern matching
- Score calculation

**MLEngine** (`src/detection/ml-engine.ts`)
- Feature vector generation
- ML scoring (rule-based)
- Expandable to real ML model

**Service Worker** (`src/background/service-worker.ts`)
- URL interception
- Statistics tracking
- Message handling

**Content Script** (`src/content/content-script.ts`)
- Page behavior monitoring
- Form analysis
- User warnings

## Configuration

### Adjusting Sensitivity

**Decrease False Positives:**
```typescript
// In config.ts
RISK_THRESHOLDS: {
  HIGH: 80,  // Increase from 70
  CRITICAL: 95  // Increase from 90
}

HEURISTIC_WEIGHTS: {
  IP_URL: 30,  // Decrease from 40
  SUSPICIOUS_TLD: 20  // Decrease from 25
}
```

**Increase Protection:**
```typescript
RISK_THRESHOLDS: {
  MEDIUM: 40,  // Decrease from 50
  HIGH: 60  // Decrease from 70
}
```

### Adding Custom TLDs

```typescript
// In config.ts
SUSPICIOUS_TLDS: [
  'tk', 'ml', 'ga', 'cf', 'gq', 'zip',
  'loan', 'click', 'work', 'party',
  'yourCustomTLD'  // Add here
]
```

### Adding Brand Monitoring

```typescript
// In config.ts
TARGETED_BRANDS: [
  'paypal', 'google', 'microsoft',
  'yourBrand'  // Add here
]
```

## Extending Functionality

### Adding New API Integration

1. **Add to SignatureEngine:**

```typescript
public static async checkNewAPI(url: string): Promise<APIResponse> {
  try {
    const response = await fetch(`https://api.example.com/check?url=${url}`);
    const data = await response.json();
    
    return {
      success: true,
      malicious: data.is_malicious,
      source: 'NewAPI',
      details: data
    };
  } catch (error) {
    return {
      success: false,
      malicious: false,
      source: 'NewAPI',
      error: error.message
    };
  }
}
```

2. **Add to checkAllAPIs:**

```typescript
public static async checkAllAPIs(url: string): Promise<DetectionLayer[]> {
  const results = await Promise.allSettled([
    this.checkSafeBrowsing(url),
    this.checkPhishTank(url),
    this.checkVirusTotal(url),
    this.checkNewAPI(url)  // Add here
  ]);
  // ... rest of code
}
```

### Adding New Heuristic

1. **Add to HeuristicEngine.analyze:**

```typescript
// Check for new pattern
if (someCondition) {
  layers.push({
    layer: 'heuristic',
    method: 'New Detection Method',
    score: 25,
    details: 'Description of what was detected',
    matched: true
  });
}
```

2. **Add weight to config:**

```typescript
HEURISTIC_WEIGHTS: {
  // ... existing weights
  NEW_DETECTION: 25
}
```

## Performance Optimization

### Caching Strategy

- **Safe URLs:** Cached for 1 hour
- **Malicious URLs:** Cached for 24 hours
- **Max cache size:** 10,000 entries
- **Eviction:** LRU (Least Recently Used)

### Rate Limiting

- **Safe Browsing:** 60 requests/minute
- **VirusTotal:** 500 requests/day (free tier)
- **PhishTank:** No official limit (be respectful)

### API Optimization

- Use `Promise.allSettled()` for parallel API calls
- Fail gracefully if APIs are down
- Cache aggressively
- Implement exponential backoff for rate limits

## Troubleshooting

### Extension Not Loading
- Check `dist/` folder exists and contains files
- Verify manifest.json is valid JSON
- Check browser console for errors

### URLs Not Being Checked
- Open service worker console
- Check for errors in background script
- Verify webRequest permissions

### API Errors
- Check API keys are correct
- Verify API quotas not exceeded
- Check network tab for failed requests

### False Positives
- Add domain to whitelist
- Adjust threshold values in config
- Review heuristic weights

## Building for Production

### Before Release

1. **Remove Debug Code:**
   - Remove console.log statements
   - Set production config

2. **Test Thoroughly:**
   - Test on multiple browsers
   - Test with various URLs
   - Test API integrations

3. **Optimize Assets:**
   - Minify code (webpack handles this)
   - Optimize images (if any)

4. **Update Version:**
   - Bump version in manifest.json
   - Update README.md

### Distribution

**Chrome Web Store:**
1. Create developer account ($5 one-time fee)
2. Zip dist/ folder
3. Upload to Chrome Web Store
4. Fill in listing details

**Firefox Add-ons:**
1. Create developer account (free)
2. Zip dist/ folder
3. Submit to addons.mozilla.org

## Security Considerations

### Privacy
- No user data collected
- API calls only for URL checking
- Local storage only for stats/whitelist

### Permissions
- `webRequest`: URL interception
- `storage`: Cache and settings
- `tabs`: Badge updates
- `<all_urls>`: Check any URL

### API Keys
- **Never commit API keys to git**
- Use environment variables in production
- Rotate keys regularly

## Support

- **Issues:** Create GitHub issue
- **Questions:** Check README.md
- **Contributions:** Pull requests welcome

## License

MIT License - Free to use, modify, and distribute
