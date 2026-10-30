'use strict';
let extractionToken = '';
window.phishlensExtra = () => ({previous_messages:$('previous-messages').value,
  sender:$('sender').value,previous_sender:$('previous-sender').value,
  initiated:$('initiated').checked,extraction_token:extractionToken});

function downloadJSON(data, name) {
  const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));
  const a=el('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function resetReport(message='Inputs changed. Analyze again to generate a report.') {
  currentReport=null;$('result').replaceChildren(el('h2','Ready to analyze'),el('p',message));
}
function clearImport() {extractionToken='';$('source-file').value='';$('extract-status').textContent='Imported metadata cleared.';resetReport();}
for(const id of ['message','url','previous-messages','sender','previous-sender','initiated'])$(id).addEventListener('input',()=>resetReport());
$('clear-import').addEventListener('click',clearImport);
for(const button of document.querySelectorAll('[data-sample]')) button.addEventListener('click',clearImport);
$('extract-file').addEventListener('click',async()=>{
  const file=$('source-file').files[0];
  if(!file){$('extract-status').textContent='Choose a file first.';return;}
  $('extract-file').disabled=true;$('extract-status').textContent='Extracting locally…';
  extractionToken='';
  try {
    const form=new FormData();form.append('file',file);
    const response=await fetch('/api/extract',{method:'POST',headers:{'X-CSRF-Token':token},body:form});
    const data=await response.json();if(!response.ok)throw Error(data.error||'Extraction failed.');
    $('message').value=data.text;$('url').value='';extractionToken=data.extraction_token;
    resetReport('Review the extracted content, then Analyze.');
    if(data.sender)$('sender').value=data.sender;
    $('extract-status').textContent=`${data.kind==='email'?'Email extracted':`Image extracted · ${data.qr_values.length} QR payloads · OCR confidence ${data.ocr_confidence??'unavailable'}`}. ${data.warnings.join(' ')} Review the text, then Analyze.`;
  }catch(e){$('extract-status').textContent=e.message;}
  finally{$('extract-file').disabled=false;}
});

document.addEventListener('phishlens-report',event=>{
  const r=event.detail, root=$('result'), section=el('section',undefined,'advanced-report');
  if(r.triage) section.append(el('h2',r.triage==='review'?'Hybrid triage: review recommended':'Hybrid triage: few indicators'));
  if(r.model){
    section.append(el('h3','Experimental language model'));
    section.append(el('p',r.model.assessed ? `Model score ${r.model.score} · ${r.model.label} · ${r.model.version}` : 'No model assessment available.'));
    section.append(el('p',r.model.warning,'warning'));
    if(r.model.evidence){const detail=el('details');detail.append(el('summary','Model word evidence'));
      for(const f of r.model.evidence)detail.append(el('p',`${f.term}: ${f.weight>0?'supports phishing':'supports legitimate'} (${f.weight})`,'small'));
      section.append(detail);}
  }
  for(const [name,data] of [['Conversation context',r.context],['Imported source',r.source]]){
    if(!data)continue;
    const detail=el('details');detail.append(el('summary',name));
    if(data.note)detail.append(el('p',data.note));
    for(const f of data.findings||[]) detail.append(el('h3',f.label),el('p',f.evidence,'evidence'),el('p',f.tip||'Verify this discrepancy with the sender through a known channel.'));
    if(data.text_edited)detail.append(el('p','Extracted text was edited; source observations describe the original file.','warning'));
    if(data.attachments?.length)detail.append(el('p',`Attachments (not opened): ${data.attachments.join(', ')}`));
    for(const header of data.authentication_headers||[])detail.append(el('p',`Unverified header: ${header}`,'evidence'));
    section.append(detail);
  }
  root.prepend(section);
  if(r.saved && r.scan_id){
    const box=el('div',undefined,'feedback-box'), label=el('label','Suggest a corrected label for this saved scan');
    const select=el('select');select.setAttribute('aria-label','Feedback label');
    for(const v of ['phishing','legitimate']){const option=el('option',v);option.value=v;select.append(option);}
    const note=el('textarea');note.maxLength=1000;note.placeholder='Reason (optional)';note.setAttribute('aria-label','Feedback reason');
    const send=el('button','Submit for local review'),status=el('p');
    send.addEventListener('click',async()=>{send.disabled=true;try{
      await api('/api/feedback',{method:'POST',body:JSON.stringify({scan_id:r.scan_id,label:select.value,note:note.value})});
      status.textContent='Pending review in Evaluation & feedback. This does not train the model.';
    }catch(e){status.textContent=e.message;send.disabled=false;}});
    box.append(label,select,note,send,status);root.append(box);
  }else root.append(el('p','To submit feedback, explicitly save a scan first. Private scans are not stored for review.','small'));
});

async function networkCheck(kind, button){
  const root=$('network-result');root.replaceChildren();
  if(!$('network-consent').checked){root.append(el('p','Confirm URL sharing before running this check.','warning'));return;}
  button.disabled=true;root.append(el('p','Running the selected online check…'));
  try{
    const result=await api(`/api/network/${kind}`,{method:'POST',body:JSON.stringify({url:$('network-url').value,consent:true})});
    root.replaceChildren();
    if(kind==='reputation'){
      root.append(el('h3',`URLhaus: ${result.urlhaus.status.replaceAll('_',' ')}`),el('p',result.urlhaus.detail||result.urlhaus.threat||'No additional provider details.'));
      root.append(el('p',`Registration: ${result.registration.status}${result.cached?' · Cached for up to 15 minutes':''}`));
      for(const event of result.registration.events||[])root.append(el('p',`${event.action}: ${event.date}`));
    }else{
      root.append(el('h3',result.title||'Inspection result'),el('p',`Final URL: ${result.url}`),el('p',`Password fields: ${result.password_fields} · Cross-host forms: ${result.cross_host_forms.length}`));
      for(const hop of result.chain)root.append(el('p',`${hop.status} · ${hop.url}`,'evidence'));
      for(const destination of result.cross_host_forms)root.append(el('p',`Form destination: ${destination}`,'warning'));
    }
    root.append(el('p',result.warning,'warning'));
    const download=el('button','Download online report');download.addEventListener('click',()=>downloadJSON(result,'phishlens-online.json'));root.append(download);
  }catch(e){root.replaceChildren(el('p',e.message,'warning'));}finally{button.disabled=false;}
}
$('check-reputation').addEventListener('click',e=>networkCheck('reputation',e.currentTarget));
$('inspect-website').addEventListener('click',e=>networkCheck('inspect',e.currentTarget));

function metricTable(report){
  const wrap=el('div',undefined,'table-wrap'),table=el('table'),head=el('tr');
  for(const name of ['Engine','Precision','Recall','False alarms','Missed phishing'])head.append(el('th',name));
  table.append(head);
  for(const name of ['rule','model','hybrid']){const m=report[name];if(!m)continue;
    const row=el('tr');for(const value of [name,`${(100*m.precision).toFixed(1)}%`,`${(100*m.recall).toFixed(1)}%`,m.false_positive,m.false_negative])row.append(el('td',value));table.append(row);}
  wrap.append(table);return wrap;
}
async function dashboard(){
  $('dashboard-status').textContent='Loading…';
  try{
    const data=await api('/api/dashboard'),root=$('dashboard-content');root.replaceChildren();
    root.append(el('p',`Saved scans: ${Object.entries(data.history_counts).map(([k,v])=>`${k}: ${v}`).join(' · ')||'none'}`));
    root.append(el('p',`Earlier rules ${data.baseline.ruleset_version}: reserved-set precision ${(data.baseline.precision*100).toFixed(1)}%, recall ${(data.baseline.recall*100).toFixed(1)}%. Synthetic data only.`,'small'));
    if(data.reviewed_report)root.append(el('h3','Current engines on reviewed feedback'),metricTable(data.reviewed_report),el('p',data.reviewed_report.warning,'warning'));
    for(const run of data.runs){const detail=el('details');if(run===data.runs[0])detail.open=true;
      detail.append(el('summary',`${run.created_at} UTC · ${run.report.ruleset_version} / ${run.report.model_version} · ${run.report.split}`),metricTable(run.report),el('p',run.report.warning,'warning'));
      for(const [category,report] of Object.entries(run.report.categories)){const group=el('details');group.append(el('summary',category),metricTable(report));detail.append(group);}root.append(detail);}
    root.append(el('h2','Feedback review queue'));
    if(!data.feedback.length)root.append(el('p','No feedback yet. Save a scan and submit a suggested label from its report.'));
    for(const item of data.feedback){const card=el('article',undefined,'history-item');
      card.append(el('h3',`Scan ${item.scan_id} · ${item.status} · suggested ${item.suggested_label}`),el('p',item.message),el('p',item.note));
      if(item.status==='pending')for(const label of ['phishing','legitimate','reject']){const button=el('button',label==='reject'?'Reject':`Approve as ${label}`);
        button.addEventListener('click',async()=>{try{await api(`/api/feedback/${item.id}/review`,{method:'POST',body:JSON.stringify({label})});await dashboard();}catch(e){$('dashboard-status').textContent=e.message;}});card.append(button);}
      root.append(card);
    }
    $('dashboard-status').textContent='Feedback remains local; only reviewed labels are exported. Shows the latest 100 feedback entries and 20 evaluation runs.';
  }catch(e){$('dashboard-status').textContent=e.message;}
}
$('dashboard-tab').addEventListener('click',()=>{showView(false);$('analyzer-view').hidden=true;$('dashboard-view').hidden=false;$('analyzer-tab').setAttribute('aria-pressed','false');$('dashboard-tab').setAttribute('aria-pressed','true');dashboard();});
$('refresh-dashboard').addEventListener('click',dashboard);
$('run-evaluation').addEventListener('click',async()=>{
  $('run-evaluation').disabled=true;$('dashboard-status').textContent='Evaluating rules, classifier and hybrid decisions…';
  try{await api('/api/evaluations',{method:'POST',body:JSON.stringify({split:'heldout'})});await dashboard();}
  catch(e){$('dashboard-status').textContent=e.message;}finally{$('run-evaluation').disabled=false;}
});
$('export-feedback').addEventListener('click',async()=>{try{downloadJSON(await api('/api/feedback/export'),'phishlens-reviewed-labels.json');}catch(e){$('dashboard-status').textContent=e.message;}});
api('/api/capabilities').then(c=>{$('capability-status').textContent=`Image packages: ${c.image_packages?'ready':'install requirements-advanced.txt'} · OCR engine: ${c.ocr_engine?'configured':'configure Tesseract'} · URLhaus: ${c.reputation_configured?'configured':'API key needed'} · Website worker: ${c.inspector_enabled&&c.docker_available?'enabled (image must be built)':'Docker/setup needed'}`;}).catch(()=>{});

// Extension handoff uses a fragment (not sent in HTTP requests). Clear it before
// displaying imported data; user still explicitly starts analysis and saving.
function importSelection(){
 if(!location.hash.startsWith('#import='))return;
  const fragment=location.hash.slice(8);history.replaceState(null,'',location.pathname);
  try{if(fragment.length>150000)throw Error('Import too large');const data=JSON.parse(decodeURIComponent(fragment));
    if(typeof data.message!=='string'||typeof data.url!=='string'||data.message.length>20000||data.url.length>2048)throw Error('Invalid import');
    extractionToken='';$('source-file').value='';$('previous-messages').value='';$('sender').value='';$('previous-sender').value='';$('initiated').checked=false;
    $('message').value=data.message;$('url').value=data.url;$('save').checked=false;$('retention-options').hidden=true;
    $('extract-status').textContent='Imported from your browser extension. Review before analyzing.';
    $('network-consent').checked=false;$('network-url').value='';$('network-result').replaceChildren();
    resetReport('Imported selection is ready. Review it, then Analyze.');showView(false);
  }catch(e){$('error').textContent='Could not import browser selection.';}
}
window.addEventListener('hashchange',importSelection);
importSelection();
