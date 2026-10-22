const AGENT="http://127.0.0.1:13872";
const TOKEN="__LOCAL_PAIRING_TOKEN__";
const seen=new Set();
async function scan() {
  const tabs=await chrome.tabs.query({url:["https://hpanel.hostinger.com/*"]});
  if(!tabs.length) return {ok:false,status:"HPANEL_TAB_REQUIRED",domains:[]};
  const tab=tabs.find(t=>t.active)||tabs[0];
  try {
    const [res]=await chrome.scripting.executeScript({target:{tabId:tab.id},func:()=>{
      if(location.hostname!=="hpanel.hostinger.com" || !location.pathname.startsWith("/websites"))
        return {status:"WEBSITES_PAGE_REQUIRED",sites:[]};
      const domainPattern=/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,24}$/i;
      const excluded=new Set(["gmail.com","outlook.com","hotmail.com","yahoo.com","icloud.com"]);
      const results=new Map();
      const nodes=[...document.querySelectorAll("a,button,[role='link'],[data-testid],h2,h3,h4,p,span")];
      for(const el of nodes){
        const label=(el.textContent||"").trim();
        if(label.length>254 || !domainPattern.test(label) || excluded.has(label.toLowerCase()))continue;
        const ancestor=el.closest("article,li,[data-testid],[class*='card'],[class*='Card']");
        if(!ancestor)continue;
        const blob=(ancestor.innerText||"").trim();
        if(blob.length>1600 || blob.length<label.length)continue;
        const domain=label.toLowerCase();
        const title=blob.split("\\n").map(x=>x.trim()).filter(Boolean);
        results.set(domain,{domain,card_text:title.slice(0,12).join(" | ").slice(0,500),
          evidence:"domain_element_in_card",account:null,plan:null,status:null});
      }
      return {status:"CARD_CANDIDATES",sites:[...results.values()].slice(0,100)};
    }});
    return {ok:true,status:res.result?.status||"NO_RESULT",source:"hpanel-card-dom",sites:res.result?.sites||[],domains:(res.result?.sites||[]).map(x=>x.domain)};
  } catch(_) {return {ok:false,status:"TAB_INSPECTION_FAILED",domains:[]};}
}
async function tick(){
  try {
    const response=await fetch(AGENT+"/jobs",{headers:{"Authorization":"Bearer "+TOKEN},cache:"no-store"});
    if(!response.ok)return;
    const job=await response.json();
    if(!job.id||seen.has(job.id))return;
    seen.add(job.id);
    const result=await scan();
    await fetch(AGENT+"/results",{method:"POST",headers:{"Authorization":"Bearer "+TOKEN,"Content-Type":"application/json"},body:JSON.stringify({id:job.id,result})});
    if(seen.size>100)seen.clear();
  }catch(_){}
}
chrome.runtime.onInstalled.addListener(()=>chrome.alarms.create("poll",{periodInMinutes:0.5}));
chrome.runtime.onStartup.addListener(()=>chrome.alarms.create("poll",{periodInMinutes:0.5}));
chrome.alarms.onAlarm.addListener(a=>{if(a.name==="poll")tick()});
chrome.runtime.onMessage.addListener((msg,_sender,reply)=>{
  if(msg?.type!=="MAD4B_SCAN")return false;
  scan().then(reply);return true;
});
tick();
