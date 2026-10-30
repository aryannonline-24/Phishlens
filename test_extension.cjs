const fs=require('fs'),vm=require('vm'),assert=require('node:assert/strict'),path=require('path');
(async()=>{
 const elements={},sent=[];
 for(const id of ['read','send','message','url','status'])elements[id]={value:'',textContent:'',addEventListener:(event,fn)=>elements[id].click=fn};
 const context={document:{getElementById:id=>elements[id]},window:{close:()=>{}},chrome:{
  tabs:{query:async()=>[{id:1,url:'https://example.com/login'}],create:async data=>sent.push(data)},
  scripting:{executeScript:async()=>[{result:'Please check this message'}]}
 }};
 vm.runInNewContext(fs.readFileSync(path.join(__dirname,'extension/popup.js'),'utf8'),context);
 assert.equal(sent.length,0);
 await elements.read.click();assert.equal(sent.length,0);assert.equal(elements.message.value,'Please check this message');
 await elements.send.click();assert.equal(sent.length,1);
 const handoff=new URL(sent[0].url);assert.equal(handoff.origin,'http://127.0.0.1:5000');assert.equal(handoff.search,'');
 assert.equal(JSON.parse(decodeURIComponent(handoff.hash.slice(8))).message,'Please check this message');
 const manifest=JSON.parse(fs.readFileSync(path.join(__dirname,'extension/manifest.json')));
 assert.deepEqual(manifest.permissions,['activeTab','scripting']);assert.equal(manifest.host_permissions,undefined);
 elements.url.value='javascript:alert(1)';await elements.send.click();assert.equal(sent.length,1);
 console.log('Extension permission, explicit activation, handoff and scheme checks passed.');
})().catch(e=>{console.error(e);process.exitCode=1;});
