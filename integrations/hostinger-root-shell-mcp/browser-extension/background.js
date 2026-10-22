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
      const domainPattern=/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i;
      const emailPattern=/\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi;
      const allDomains=/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;
      const excluded=new Set(["gmail.com","outlook.com","hotmail.com","yahoo.com","icloud.com"]);
      const results=new Map();
      const nodes=[...document.querySelectorAll("a,button,[role='link'],[data-testid],h2,h3,h4,p,span")];
      for(const el of nodes){
        const label=(el.textContent||"").trim();
        if(label.length>253 || !domainPattern.test(label) || excluded.has(label.toLowerCase())) continue;
        const domain=label.toLowerCase();
        let siteCard=null, group=null;
        // A site card MUST contain its own domain and the site's Manage site control.
        // The closest matching ancestor wins; never reuse another site's card text.
        for(let parent=el.parentElement;parent&&parent!==document.body;parent=parent.parentElement){
          const text=(parent.innerText||"").trim();
          if(!text || text.length>24000) break;
          if(!siteCard && text.length<1800 && text.includes(label) &&
             /manage site/i.test(text)) {
            const found=[...new Set((text.match(allDomains)||[])
              .map(x=>x.toLowerCase()).filter(x=>!excluded.has(x)))];
            if(found.length===1 && found[0]===domain) siteCard=parent;
          }
          // Scope hosting account/plan to nearest group with one unique account email.
          if(!group && text.length<24000 && /plan expires on/i.test(text) && text.includes(label)){
            const emails=[...new Set((text.match(emailPattern)||[]).map(x=>x.toLowerCase()))];
            if(emails.length===1){
              const expiry=text.match(/plan expires on\s+(\d{4}-\d{2}-\d{2})/i);
              const lines=text.split(/\n/).map(x=>x.trim()).filter(Boolean);
              const plan=lines.find(x=>/^(business web hosting|business|cloud startup|cloud professional|cloud enterprise|premium web hosting)$/i.test(x));
              group={account_email:emails[0],hosting_plan:plan||null,
                     plan_expires:expiry?expiry[1]:null,group_evidence:"single-account-hosting-group"};
            }
          }
          if(siteCard&&group) break;
        }
        if(!siteCard) continue;
        const text=(siteCard.innerText||"").trim();
        const type=/\bWordPress\b/i.test(text)?"WordPress":
                   /\bAI Builder\b/i.test(text)?"AI Builder":null;
        const created=text.match(/created\s+(\d{4}-\d{2}-\d{2})/i);
        const site={domain,site_type:type,created_on:created?created[1]:null,
          site_status:null,listed_in_hpanel:true,evidence:"unique_domain_and_manage_site_in_card",
          account_email:group?.account_email||null,hosting_plan:group?.hosting_plan||null,
          plan_expires:group?.plan_expires||null,group_evidence:group?.group_evidence||null};
        results.set(domain,site);
      }
      const unresolved=[...new Set(((document.body?.innerText||"").replace(emailPattern," ").match(allDomains)||[]).map(x=>x.toLowerCase()))]
        .filter(x=>!excluded.has(x)&&!results.has(x)).slice(0,100);
      return {status:"SCOPED_CARD_CANDIDATES",sites:[...results.values()].slice(0,100),unresolved_domains:unresolved};
    }});
    return {ok:true,status:res.result?.status||"NO_RESULT",source:"hpanel-card-dom",sites:res.result?.sites||[],unresolved_domains:res.result?.unresolved_domains||[],domains:(res.result?.sites||[]).map(x=>x.domain)};
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
