// UI Panels Module
// Contains rendering logic for SOC panels and collapsible card helpers.

function renderCombinedPanel() {
    const container = document.getElementById('combinedResults');

    if (!currentResults.vt && !currentResults.abuseipdb && !currentResults.whois && !currentResults.urlscan) {
        container.innerHTML = '<div class="empty-state"><span>Run scans to see combined analysis</span></div>';
        return;
    }

    let riskScore = 0;
    let vtMalicious = 0;
    let vtTotal = 0;
    if (currentResults.vt && currentResults.vt.data && currentResults.vt.data.attributes) {
        const stats = currentResults.vt.data.attributes.last_analysis_stats;
        vtTotal = Object.values(stats).reduce((a, b) => a + b, 0);
        vtMalicious = stats.malicious + stats.suspicious;
        if (vtMalicious > 0) riskScore += 40;
    }

    let abuseConfidence = 0;
    if (currentResults.abuseipdb && currentResults.abuseipdb.abuseConfidenceScore !== undefined) {
        abuseConfidence = currentResults.abuseipdb.abuseConfidenceScore || 0;
        if (abuseConfidence > 25) riskScore += 25;
    }

    let urlscanScore = 0;
    if (currentResults.urlscan && currentResults.urlscan.verdicts && currentResults.urlscan.verdicts.overall) {
        const overall = currentResults.urlscan.verdicts.overall;
        urlscanScore = overall.score || 0;
        if (urlscanScore > 50) riskScore += 20;
    }

    let domainAge = null;
    if (currentResults.whois && currentResults.whois.creation_date) {
        const creationDate = new Date(currentResults.whois.creation_date);
        const now = new Date();
        const ageDays = Math.floor((now - creationDate) / (1000 * 60 * 60 * 24));
        domainAge = ageDays;
        if (ageDays < 30) riskScore += 15;
    }

    const threatScore = Math.min(100, riskScore);

    let verdictCategory = '';
    let verdictClass = '';
    if (threatScore <= 20) {
        verdictCategory = 'LOW RISK';
        verdictClass = 'low';
    } else if (threatScore <= 50) {
        verdictCategory = 'SUSPICIOUS';
        verdictClass = 'suspicious';
    } else {
        verdictCategory = 'HIGH RISK';
        verdictClass = 'high';
    }

    let recommendation = '';
    let recommendationClass = '';
    if (threatScore < 20) {
        recommendation = 'ALLOW';
        recommendationClass = 'allow';
    } else if (threatScore <= 50) {
        recommendation = 'REVIEW';
        recommendationClass = 'review';
    } else {
        recommendation = 'BLOCK';
        recommendationClass = 'block';
    }

    const typeIcon = currentResults.type === 'ip' ? '🖥' : currentResults.type === 'domain' ? '📧' : currentResults.type === 'url' ? '🌐' : currentResults.type === 'hash' ? '📄' : '🔍';
    let html = '';

    html += '<div class="quick-actions-bar">';
    html += '<button onclick="copyIOC()" class="quick-action-btn">📋 Copy IOC</button>';
    html += '<button onclick="copyCombinedResults()" class="quick-action-btn">📄 Copy Report</button>';
    html += '<button onclick="exportTXT()" class="quick-action-btn">💾 Export</button>';
    html += '</div>';

    html += '<div class="ioc-header-bar">';
    html += '<div class="ioc-header-main">';
    html += '<span class="ioc-icon">' + typeIcon + '</span>';
    html += '<span class="ioc-value">' + currentResults.ioc + '</span>';
    html += '<span class="ioc-type-badge">' + (currentResults.type || 'N/A').toUpperCase() + '</span>';
    html += '</div>';
    html += '<div class="sources-indicator">';
    let sources = [];
    if (currentResults.vt) sources.push('VirusTotal');
    if (currentResults.abuseipdb) sources.push('AbuseIPDB');
    if (currentResults.whois) sources.push('WHOIS');
    if (currentResults.urlscan) sources.push('URLScan');
    html += '📡 Sources: ' + (sources.length > 0 ? sources.join(' | ') : 'None');
    html += '</div>';
    html += '</div>';

    html += '<div class="soc-card"><div id="threat-score-header" class="soc-card-header expanded" onclick="toggleSocCard(\'threat-score\')"><h3>🎯 Threat Confidence Score</h3><span id="threat-score-toggle" class="soc-card-toggle">▼</span></div>';
    html += '<div id="threat-score-body" class="soc-card-body"><div class="threat-score-container">';
    const meterColor = threatScore >= 51 ? 'var(--accent-red)' : threatScore >= 21 ? 'var(--accent-yellow)' : 'var(--accent-green)';
    html += '<div class="threat-score-meter"><div class="threat-score-fill" style="width:' + threatScore + '%;background:linear-gradient(90deg,' + meterColor + ',' + meterColor + 'aa);"></div></div>';
    html += '<div class="threat-score-value" style="color:' + meterColor + ';">' + threatScore + '%</div>';
    html += '<div class="threat-verdict-badge ' + verdictClass + '">' + verdictCategory + '</div>';
    html += '<div class="score-breakdown">';
    html += '<div class="score-breakdown-item"><span class="score-breakdown-source">VirusTotal Detections</span><span class="score-breakdown-value">' + (vtMalicious > 0 ? '+40' : '0') + '</span></div>';
    html += '<div class="score-breakdown-item"><span class="score-breakdown-source">AbuseIPDB Confidence (>25%)</span><span class="score-breakdown-value">' + (abuseConfidence > 25 ? '+25' : '0') + '</span></div>';
    html += '<div class="score-breakdown-item"><span class="score-breakdown-source">URLScan Verdict (>50)</span><span class="score-breakdown-value">' + (urlscanScore > 50 ? '+20' : '0') + '</span></div>';
    html += '<div class="score-breakdown-item"><span class="score-breakdown-source">Domain Age (<30 days)</span><span class="score-breakdown-value">' + (domainAge !== null && domainAge < 30 ? '+15' : '0') + '</span></div>';
    html += '<div class="score-breakdown-total"><span>Total Score</span><span>' + threatScore + ' / 100</span></div></div></div></div></div>';

    html += '<div class="soc-card"><div id="recommendation-header" class="soc-card-header expanded" onclick="toggleSocCard(\'recommendation\')"><h3>💡 Analyst Recommendation</h3><span id="recommendation-toggle" class="soc-card-toggle">▼</span></div>';
    html += '<div id="recommendation-body" class="soc-card-body"><div class="recommendation-box ' + recommendationClass + '">';
    html += '<div class="threat-verdict-badge ' + verdictClass + '" style="margin-bottom:12px;">Risk Level: ' + verdictCategory + '</div>';
    html += '<div class="recommendation-action">' + recommendation + '</div></div></div></div>';

    container.innerHTML = html;
}

function toggleCardPanel(header) {
    const body = header.nextElementSibling;
    body.classList.toggle('collapsed');
    const arrow = header.querySelector('span');
    arrow.textContent = body.classList.contains('collapsed') ? '▶' : '▼';
}

function toggleSocCardPanel(cardId) {
    const header = document.getElementById(cardId + '-header');
    const body = document.getElementById(cardId + '-body');
    const toggle = document.getElementById(cardId + '-toggle');

    if (header && body && toggle) {
        header.classList.toggle('expanded');
        body.classList.toggle('collapsed');
        toggle.classList.toggle('collapsed');
    }
}
