chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scrape_opened_email') {
    let sender = 'Unknown Sender';
    let subject = 'Unknown Subject';
    let bodyText = '';
    let links = [];

    // Gmail DOM Selectors
    const gmailSenderElem = document.querySelector('span.gD');
    if (gmailSenderElem) sender = gmailSenderElem.getAttribute('email') || gmailSenderElem.innerText;

    const gmailSubjectElem = document.querySelector('h2.hP');
    if (gmailSubjectElem) subject = gmailSubjectElem.innerText;

    const gmailBodyElem = document.querySelector('div.a3s');
    if (gmailBodyElem) {
      bodyText = gmailBodyElem.innerText;
      const anchorElems = gmailBodyElem.querySelectorAll('a[href]');
      anchorElems.forEach(a => links.push(a.href));
    }

    // Fallback for generic webmail views
    if (!bodyText) {
      bodyText = document.body.innerText;
      document.querySelectorAll('a[href]').forEach(a => links.push(a.href));
    }

    sendResponse({
      sender: sender,
      subject: subject,
      body_text: bodyText.substring(0, 3000), // Cap length
      links: Array.from(new Set(links)) // Deduplicate links
    });
  }
  return true;
});