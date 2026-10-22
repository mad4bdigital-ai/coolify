const AGENT="http://127.0.0.1:13872";
const TOKEN="__LOCAL_PAIRING_TOKEN__";
const seen=new Set();
async function scan() {
  const tabs=await chrome.tabs.query({url:["https://hpanel.hostinger.com/*"]});
  if(!tabs.length) return {ok:false,status:"HPANEL_TAB_REQUIRED",domains:[]};
  const tab=tabs.find(t=>t.active)||tabs[0];
  try {
    const [res]=await chrome.scripting.executeScript({target:{tabId:tab.id},func:()=>{
      const body=document.body?.innerText||"";
      const candidates=new Set();
      const regex=/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;
      for(const hit of body.matchAll(regex)) candidates.add(hit[0].toLowerCase());
      return Array.from(candidates).slice(0,100);
    }});
    return {ok:true,status:"CANDIDATES_ONLY",source:"hpanel-visible-dom",domains:res.result||[]};
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
