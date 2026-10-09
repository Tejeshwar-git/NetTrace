document.addEventListener('DOMContentLoaded', () => {
  const scanBtn = document.getElementById('scanBtn');
  const scanEmailBtn = document.getElementById('scanEmailBtn');
  const statusDiv = document.getElementById('status');

  // 1. History Streamer
  if (scanBtn) {
    scanBtn.addEventListener('click', () => {
      const caseIdInput = document.getElementById('caseIdInput');
      const caseId = caseIdInput ? caseIdInput.value.trim() : '';

      if (!caseId) {
        statusDiv.style.color = '#EF4444';
        statusDiv.innerText = '⚠️ Enter a Case ID';
        return;
      }

      statusDiv.style.color = '#38BDF8';
      statusDiv.innerText = 'Extracting active history...';

      chrome.history.search({ text: '', maxResults: 100 }, (results) => {
        const formattedHistory = results.map(item => ({
          url: item.url || '',
          title: item.title || '',
          visitCount: item.visitCount || 1,
          lastVisitTime: item.lastVisitTime || 0
        }));

        fetch('http://127.0.0.1:8000/api/ingest/live-extension', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ case_id: caseId, history: formattedHistory })
        })
        .then(async (res) => {
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          return res.json();
        })
        .then((json) => {
          statusDiv.style.color = '#10B981';
          statusDiv.innerText = `✅ Streamed ${json.total_scanned} URLs!`;
        })
        .catch((err) => {
          statusDiv.style.color = '#EF4444';
          statusDiv.innerText = `❌ ${err.message}`;
        });
      });
    });
  }

  // 2. Webmail Active Scanner
  if (scanEmailBtn) {
    scanEmailBtn.addEventListener('click', () => {
      const caseIdInput = document.getElementById('caseIdInput');
      const caseId = caseIdInput ? caseIdInput.value.trim() : '';

      statusDiv.style.color = '#38BDF8';
      statusDiv.innerText = 'Scrape active email page...';

      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs[0]) return;
        
        chrome.tabs.sendMessage(tabs[0].id, { action: 'scrape_opened_email' }, (emailData) => {
          if (!emailData || !emailData.body_text) {
            statusDiv.style.color = '#EF4444';
            statusDiv.innerText = '⚠️ No active email content detected.';
            return;
          }

          emailData.case_id = caseId;

          fetch('http://127.0.0.1:8000/api/parse/live-email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(emailData)
          })
          .then(async (res) => {
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            return res.json();
          })
          .then((json) => {
            const badge = json.score >= 60 ? '🚨 HIGH RISK' : (json.score >= 30 ? '⚠️ MEDIUM RISK' : '✅ CLEAN');
            statusDiv.style.color = json.score >= 50 ? '#EF4444' : '#10B981';
            statusDiv.innerText = `${badge} (${json.score}% Risk Score)`;
          })
          .catch((err) => {
            statusDiv.style.color = '#EF4444';
            statusDiv.innerText = `❌ ${err.message}`;
          });
        });
      });
    });
  }
});