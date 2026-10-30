'use strict';
const $ = id => document.getElementById(id);
const token = document.querySelector('meta[name="csrf-token"]').content;
let currentReport = null, historyPage = 1, historyTotal = 0;
const el = (tag, value, cls) => { const n = document.createElement(tag); if(value !== undefined) n.textContent = value; if(cls) n.className = cls; return n; };
async function api(path, options={}) {
  const res = await fetch(path, {...options, headers:{'Content-Type':'application/json','X-CSRF-Token':token,...options.headers}});
  const data = await res.json(); if(!res.ok) throw new Error(data.error || 'Request failed.'); return data;
}
function showView(history) {
  $('dashboard-view').hidden=true;$('dashboard-tab').setAttribute('aria-pressed','false');
  $('history-view').hidden = !history; $('analyzer-view').hidden = history;
  $('history-tab').setAttribute('aria-pressed',String(history)); $('analyzer-tab').setAttribute('aria-pressed',String(!history));
}
function renderReport(r) {
  currentReport = r;
  const root = $('result'); root.replaceChildren();
  const findings = [...r.message_findings,...r.url_findings].filter(f=>f.triggered).sort((a,b)=>b.contribution-a.contribution);
  const titles = {low:'Few warning signs detected',medium:'Warning signs detected',high:'Strong warning signs detected'};
  root.append(el('p',r.analysis_complete ? titles[r.risk] : 'Incomplete URL analysis', `rating ${r.risk}`));
  const lead = el('div',undefined,'takeaway');
  lead.append(el('h3',findings.length ? findings[0].label : 'Verify unexpected requests independently'));
  if(findings.length) lead.append(el('p',findings[0].evidence,'evidence'));
  lead.append(el('p',`Next step: ${!r.analysis_complete ? 'Verify the destination independently; some links could not be analysed.' : findings.length ? findings[0].tip : 'Contact the sender through a known channel before sharing information or paying.'}`));
  for(const u of r.url_reports) lead.append(el('p',u.valid ? `Actual destination: ${u.hostname} · Registered domain: ${u.registered_domain}` : `Unresolved destination: ${u.raw}`, 'destination'));
  root.append(lead);
  root.append(el('p',`Score ${r.score} · Message ${r.message_score} + URL indicators ${r.url_score}`, 'scores'));
  root.append(el('p',`Thresholds: Medium ${r.thresholds.medium}, High ${r.thresholds.high}. Rule set ${r.ruleset_version}.`, 'small'));
  for(const warning of r.warnings) root.append(el('p',warning,'warning'));
  root.append(el('h3',`Detected indicators (${findings.length})`));
  if(!findings.length) root.append(el('p','No configured indicators matched. Independently verify unexpected requests.'));
  for(const f of findings) {
    const block=el('div',undefined,'finding'); block.append(el('h3',`${f.label} (+${f.contribution})`),el('p',f.evidence,'evidence'),el('p',f.tip));root.append(block);
  }
  if(r.url_reports.length) {
    const details=el('details');details.append(el('summary',`URL details (${r.url_reports.length})`));
    for(const u of r.url_reports) {const block=el('div',undefined,'url-report');block.append(el('strong',u.raw));block.append(el('p',u.valid?`Destination: ${u.hostname}\nRegistered domain: ${u.registered_domain}\nURL score: ${u.score} (${u.risk})`:u.error));if(u.normalization_applied) block.append(el('p',`Normalized for analysis: ${u.normalized_url} (no link visited)`, 'evidence'));details.append(block);}root.append(details);
  }
  const all=el('details');all.append(el('summary','All configured checks'));
  for(const f of [...r.message_findings,...r.url_findings]) all.append(el('p',`${f.triggered?'Matched':'Not matched'}: ${f.label}`, 'small'));
  if(!r.has_url) all.append(el('p','URL checks were not assessed because no URL was provided.','small'));
  root.append(all,el('p',r.saved?'Saved locally.':'This view does not save a new scan.','small'));
  const download=el('button','Download JSON report');download.type='button';download.addEventListener('click',()=>{
    const uri=URL.createObjectURL(new Blob([JSON.stringify(currentReport,null,2)],{type:'application/json'}));const a=el('a');a.href=uri;a.download='phishlens-report.json';a.click();URL.revokeObjectURL(uri);
  });root.append(download);
  document.dispatchEvent(new CustomEvent('phishlens-report',{detail:r}));
}
$('scan-form').addEventListener('submit',async event=>{
  event.preventDefault();$('error').textContent='';$('submit').disabled=true;$('submit').textContent='Analyzing…';
  try {const r=await api('/analyze',{method:'POST',body:JSON.stringify({message:$('message').value,url:$('url').value,save_history:$('save').checked,retention_days:Number($('retention').value),...(window.phishlensExtra ? window.phishlensExtra() : {})})});renderReport(r);}
  catch(e){$('error').textContent=e.message;}finally{$('submit').disabled=false;$('submit').textContent='Analyze message';}
});
$('save').addEventListener('change',()=>{$('retention-options').hidden=!$('save').checked;});
const samples={hr:['Hi, this is Priya from HR. Could you quickly confirm your employee ID on this portal before end of day?','http://hr-portal-verify.com/login'],hinglish:['KYC abhi update karo warna account band ho jayega. Apna OTP bhejo.',''],disguised:['Review this notice at hxxps://paypal[.]com.attacker-example.com/login',''],phishing:['Dear Customer, send your OTP immediately or your account will be suspended!!!','http://paypa1.com/login'],legitimate:['Your OTP is 123456. Do not share this OTP with anyone.',''],domain:['Please check this account notice.','https://paypal.com.attacker-example.test/login']};
for(const button of document.querySelectorAll('[data-sample]'))button.addEventListener('click',()=>{const [message,url]=samples[button.dataset.sample];$('message').value=message;$('url').value=url;});
async function loadHistory() {
  $('history-status').textContent='Loading…';
  try {
    const q=new URLSearchParams({q:$('search').value,risk:$('risk-filter').value,page:historyPage});const data=await api('/api/history?'+q);historyTotal=data.total;
    if(!data.items.length && historyPage>1){historyPage--;return loadHistory();}
    $('history-list').replaceChildren();$('history-status').textContent=`${data.total} saved scans`;
    for(const scan of data.items){const card=el('article',undefined,'history-item');card.append(el('h3',`${scan.computed_risk.toUpperCase()} · Score ${scan.computed_score}`),el('p',(scan.message_text||'').slice(0,240)+((scan.message_text||'').length>240?'…':'')),el('p',scan.url,'small'),el('p',`${scan.timestamp} UTC · Rules ${scan.ruleset_version||'legacy'}`,'small'));
      card.append(el('p',scan.expires_at ? `Auto-delete after ${scan.expires_at} UTC when the app is used.` : 'Kept until manually deleted.', 'small'));
      const actions=el('div',undefined,'history-actions'),view=el('button','View report'),remove=el('button','Delete','danger');
      view.addEventListener('click',async()=>{try{const detail=await api(`/api/history/${scan.id}`);if(!detail.result){$('history-status').textContent='This legacy scan has no stored findings. Scan it again to generate a new report.';return;}renderReport({...detail.result,saved:true,scan_id:scan.id});showView(false);}catch(e){$('history-status').textContent=e.message;}});
      remove.addEventListener('click',async()=>{if(!confirm('Delete this saved scan?'))return;try{await api(`/api/history/${scan.id}`,{method:'DELETE'});await loadHistory();}catch(e){$('history-status').textContent=e.message;}});actions.append(view,remove);card.append(actions);$('history-list').append(card);
    }
    $('page-label').textContent=`Page ${historyPage}`;$('previous').disabled=historyPage===1;$('next').disabled=historyPage*20>=historyTotal;
  }catch(e){$('history-status').textContent=e.message;}
}
$('analyzer-tab').addEventListener('click',()=>showView(false));$('history-tab').addEventListener('click',()=>{showView(true);loadHistory();});
$('history-filter').addEventListener('submit',e=>{e.preventDefault();historyPage=1;loadHistory();});$('previous').addEventListener('click',()=>{historyPage--;loadHistory();});$('next').addEventListener('click',()=>{historyPage++;loadHistory();});
$('clear-history').addEventListener('click',async()=>{if(!confirm('Permanently delete all saved scans?'))return;try{await api('/api/history',{method:'DELETE'});historyPage=1;await loadHistory();}catch(e){$('history-status').textContent=e.message;}});
