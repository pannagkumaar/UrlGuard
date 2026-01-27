/**
 * Blocked Page Script
 * Displays threat information and handles user actions
 */

// Get URL parameters
const params = new URLSearchParams(window.location.search);
const blockedURL = params.get('url') || 'Unknown';
const tabId = parseInt(params.get('tabId') || '0');

// Load threat analysis data
async function loadThreatData() {
  try {
    const result = await chrome.storage.session.get([`blocked_${tabId}`]);
    const threatData = result[`blocked_${tabId}`];

    if (threatData) {
      displayThreatData(threatData);
    } else {
      // Fallback if data not found
      document.getElementById('urlDisplay')!.textContent = blockedURL;
      document.getElementById('reason')!.textContent = 'Site blocked due to security concerns';
    }
  } catch (error) {
    console.error('Error loading threat data:', error);
    document.getElementById('urlDisplay')!.textContent = blockedURL;
    document.getElementById('reason')!.textContent = 'Error loading threat details';
  }
}

// Display threat analysis data
function displayThreatData(data: any) {
  // URL
  document.getElementById('urlDisplay')!.textContent = data.url;

  // Risk badge
  const riskBadge = document.getElementById('riskBadge')!;
  riskBadge.textContent = `${data.riskLevel.toUpperCase()} RISK`;
  riskBadge.className = `risk-badge ${data.riskLevel}`;

  // Risk score
  document.getElementById('riskScore')!.textContent = data.riskScore.toString();

  // Detection method
  const methods = data.detectionLayers
    .filter((l: any) => l.matched)
    .map((l: any) => l.method)
    .join(', ');
  document.getElementById('detectionMethod')!.textContent = methods || 'Multiple layers';

  // Reason
  document.getElementById('reason')!.textContent = data.details;

  // Message
  const messages: { [key: string]: string } = {
    critical: '🚨 CRITICAL THREAT: This site is extremely dangerous and likely malicious.',
    high: '⚠️ HIGH RISK: This site shows strong indicators of malicious activity.',
    medium: '⚠️ MEDIUM RISK: This site has several suspicious characteristics.',
    low: '⚠️ LOW RISK: This site has some suspicious indicators.'
  };
  document.getElementById('message')!.textContent = 
    messages[data.riskLevel] || 'This site has been flagged as potentially dangerous.';

  // Detection layers
  displayDetectionLayers(data.detectionLayers);

  // Timestamp
  document.getElementById('timestamp')!.textContent = 
    `Blocked at ${new Date(data.timestamp).toLocaleString()}`;
}

// Display detection layers
function displayDetectionLayers(layers: any[]) {
  const layersList = document.getElementById('layersList')!;
  layersList.innerHTML = '';

  const matchedLayers = layers.filter(l => l.matched);
  
  if (matchedLayers.length === 0) {
    layersList.innerHTML = '<p style="color: #666;">No specific threats detected, but site flagged as precautionary measure.</p>';
    return;
  }

  matchedLayers.forEach(layer => {
    const layerDiv = document.createElement('div');
    layerDiv.className = 'layer-item matched';
    
    layerDiv.innerHTML = `
      <div class="layer-header">
        <span class="layer-name">${layer.method}</span>
        <span class="layer-score">${layer.score} points</span>
      </div>
      <div class="layer-details">${layer.details}</div>
    `;
    
    layersList.appendChild(layerDiv);
  });
}

// Button handlers
document.getElementById('goBackBtn')?.addEventListener('click', () => {
  window.history.back();
});

document.getElementById('whitelistBtn')?.addEventListener('click', async () => {
  try {
    const url = new URL(blockedURL);
    const domain = url.hostname;

    const confirmed = confirm(
      `Add ${domain} to whitelist?\n\n` +
      `This will allow all pages from this domain without blocking.`
    );

    if (confirmed) {
      await chrome.runtime.sendMessage({
        type: 'addToWhitelist',
        domain: domain
      });

      alert(`✓ ${domain} has been added to your whitelist.`);
      
      // Proceed to the site
      await chrome.runtime.sendMessage({
        type: 'proceedAnyway',
        url: blockedURL,
        tabId: tabId
      });
    }
  } catch (error) {
    alert('Error adding to whitelist: ' + error);
  }
});

document.getElementById('proceedBtn')?.addEventListener('click', async () => {
  const confirmed = confirm(
    '⚠️ Are you ABSOLUTELY SURE you want to proceed?\n\n' +
    'This site may:\n' +
    '• Steal your passwords and personal information\n' +
    '• Infect your device with malware\n' +
    '• Perform fraudulent transactions\n' +
    '• Compromise your security\n\n' +
    'Only proceed if you are 100% certain this is safe.'
  );

  if (confirmed) {
    try {
      await chrome.runtime.sendMessage({
        type: 'proceedAnyway',
        url: blockedURL,
        tabId: tabId
      });
    } catch (error) {
      console.error('Error proceeding:', error);
      window.location.href = blockedURL;
    }
  }
});

// Load data on page load
loadThreatData();
