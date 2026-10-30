'use strict';
const $=id=>document.getElementById(id);
$('read').addEventListener('click',async()=>{try{
  const [tab]=await chrome.tabs.query({active:true,currentWindow:true});
  if(!tab?.id||!/^https?:\/\//i.test(tab.url||''))throw Error('Choose an HTTP(S) page. Browser settings pages cannot be read.');
  if(tab.url.length>2048)throw Error('This URL exceeds 2,048 characters. Paste a shorter URL in the local app.');
  const [result]=await chrome.scripting.executeScript({target:{tabId:tab.id},func:()=>window.getSelection().toString().slice(0,20000)});
  $('message').value=result.result||'';$('url').value=tab.url;$('status').textContent='Read up to 20,000 selected characters. Review or remove private content before sending.';
}catch(e){$('status').textContent=e.message;}});
$('send').addEventListener('click',async()=>{try{
  const data={message:$('message').value,url:$('url').value};
  if(!data.message.trim()&&!data.url.trim())throw Error('Read a selection or enter a URL first.');
  if(data.url&&!/^https?:\/\//i.test(data.url))throw Error('Only HTTP(S) URLs are supported.');
  await chrome.tabs.create({url:'http://127.0.0.1:5000/#import='+encodeURIComponent(JSON.stringify(data))});
  window.close();
}catch(e){$('status').textContent=e.message;}});
