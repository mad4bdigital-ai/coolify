let snapshot = null;
const out = document.getElementById("out");
document.getElementById("scan").addEventListener("click", async () => {
  snapshot = null;
  const [tab] = await chrome.tabs.query({active:true,currentWindow:true});
  if (!tab || !/^https:\/\/hpanel\.hostinger\.com\//.test(tab.url || "")) {
    out.textContent = "Open hPanel first."; return;
  }
  try {
    const [result] = await chrome.scripting.executeScript({target:{tabId:tab.id},func:() => {
      const text = document.body?.innerText || "";
      const hosts = new Set();
      const regex = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;
      for (const match of text.matchAll(regex)) {
        const host = match[0].toLowerCase();
        if (!/^(?:hostinger|google|cloudflare|facebook|youtube|wordpress)\.com$/.test(host)) hosts.add(host);
      }
      return {source:"hpanel-visible-dom",status:"CANDIDATES_ONLY",domains:[...hosts].slice(0,100)};
    }});
    snapshot = result.result;
    out.textContent = JSON.stringify(snapshot,null,2);
  } catch (e) { out.textContent = "Unable to inspect page: " + e.message; }
});
document.getElementById("copy").addEventListener("click", async () => {
  if (!snapshot) return;
  await navigator.clipboard.writeText(JSON.stringify(snapshot,null,2));
  out.textContent = JSON.stringify(snapshot,null,2) + "\nCopied.";
});
