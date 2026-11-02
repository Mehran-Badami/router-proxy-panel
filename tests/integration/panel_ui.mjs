// Browser-level regression tests. The server below is isolated: no real router,
// credentials, subscription downloads, or VPN operations are involved.
import assert from 'node:assert/strict';
import http from 'node:http';
import {readFile, mkdir} from 'node:fs/promises';
import {fileURLToPath, pathToFileURL} from 'node:url';
import path from 'node:path';

const {chromium} = await import(process.env.PLAYWRIGHT_MODULE_PATH
  ? pathToFileURL(process.env.PLAYWRIGHT_MODULE_PATH).href : 'playwright');
const root = fileURLToPath(new URL('../../', import.meta.url));
const html = await readFile(path.join(root, 'app/panel.html'));
const artifacts = process.env.UI_ARTIFACT_DIR;
if (artifacts) await mkdir(artifacts, {recursive:true});
const clone = value => structuredClone(value);
const originalSites = [
  {id:'youtube',name:'یوتیوب',enabled:true,subdomains:true,domains:['youtube.example','video.example']},
  {id:'custom-example',name:'برنامهٔ سفارشی',enabled:false,subdomains:false,domains:['custom.example','media.example'],note:'preserve unknown fields'},
  {id:'home',name:'خانهٔ هوشمند',enabled:true,subdomains:true,domains:['home.example']},
];
let sites={items:clone(originalSites),pending:false,configured:true,message:'اعمال قبلی تأیید شده است'};
let state={enabled:true,running:true,selected:'Server A',automatic:true,
  connectivity:{vpn_ok:true,message:'اتصال امن برقرار است',degraded:false},
  job:{running:false,message:''},scan:{running:false,message:''},
  groups:[{id:'one',name:'اشتراک شخصی',updatable:true,updated:1793577600,info:{usage:{upload:1048576,download:1073741824,total:21474836480}}},
          {id:'two',name:'اشتراک دوم',updatable:false,info:{}}],
  trash:[],servers:[
    {id:'a',name:'Server A',group:'one',host:'a.example',active:true,health:{ok:true,latency_ms:120}},
    {id:'b',name:'Server B',group:'one',host:'b.example',active:false,health:{ok:true,latency_ms:80}},
    {id:'c',name:'Server C',group:'two',host:'c.example',active:false,health:{ok:false}},
  ]};
const posts=[];
let failSave=false,failApply=false,failSites=false,delaySites=0;
const server=http.createServer(async(req,res)=>{
  res.setHeader('Content-Type',req.url==='/'?'text/html; charset=utf-8':'application/json; charset=utf-8');
  if(req.method==='GET'){
    if(req.url==='/'){res.end(html);return;}
    if(req.url==='/api/status'){res.end(JSON.stringify(state));return;}
    if(req.url==='/api/sites'){
      const snapshot=clone(sites);if(delaySites)await new Promise(r=>setTimeout(r,delaySites));
      if(failSites){res.statusCode=503;res.end(JSON.stringify({error:'خطای دریافت فهرست'}));return;}
      res.end(JSON.stringify(snapshot));return;
    }
  }
  if(req.method==='POST'){
    let raw='';for await(const c of req)raw+=c;
    const body=JSON.parse(raw);posts.push({url:req.url,body:clone(body)});
    let result={ok:true};
    if(req.url==='/api/sites/save'){
      if(failSave){res.statusCode=400;result={error:'دامنه نامعتبر است'};}
      else{sites.items=clone(body.items);sites.pending=true;result=clone(sites);}
    } else if(req.url==='/api/sites/apply'){
      if(failApply){res.statusCode=502;result={error:'روتر پاسخ نداد؛ فهرست ذخیره شده است'};}
      else{sites.pending=false;result=clone(sites);}
    } else if(req.url==='/api/sites/rollback'){sites.items=clone(originalSites);sites.pending=false;result=clone(sites);
    } else if(req.url==='/api/sites/presets'){sites.pending=true;result=clone(sites);
    } else if(req.url==='/api/automatic'){state.automatic=body.enabled;
    } else if(req.url==='/api/toggle'){state.enabled=body.enabled;
    } else if(req.url==='/api/apply'){
      state.servers.forEach(s=>s.active=s.id===body.id);state.selected=state.servers.find(s=>s.active).name;state.automatic=false;
    } else if(req.url==='/api/delete'){
      const g=state.groups.find(g=>g.id===body.group);state.trash.push(g);state.groups=state.groups.filter(g=>g.id!==body.group);state.servers=state.servers.filter(s=>s.group!==body.group);
    } else if(req.url==='/api/restore'){
      state.groups.push(state.trash.find(g=>g.id===body.id));state.trash=state.trash.filter(g=>g.id!==body.id);
    } else if(req.url==='/api/import'){
      if(body.group)state.groups.find(g=>g.id===body.group).name=body.name;
      else state.groups.push({id:'new',name:body.name,updatable:true,info:{}});
    } else if(req.url==='/api/setup/check'){
      result={ready:true,checks:[{name:'HTTPS',detail:'تأیید شد',ok:true}]};
    } else if(!['/api/test','/api/speed','/api/update','/api/recover'].includes(req.url)){
      res.statusCode=404;result={error:'Unexpected endpoint'};
    }
    res.end(JSON.stringify(result));return;
  }
  res.statusCode=404;res.end('{}');
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const origin='http://127.0.0.1:'+server.address().port;
let browser;
const errors=[];
try{
  browser=await chromium.launch({headless:true,...(process.env.UI_BROWSER_CHANNEL?{channel:process.env.UI_BROWSER_CHANNEL}:{})});
  const context=await browser.newContext({viewport:{width:390,height:844},deviceScaleFactor:1,isMobile:true,hasTouch:true});
  const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));page.on('dialog',d=>d.accept());
  const visible=selector=>page.locator(selector).waitFor({state:'visible'});
  const waitEnabled=selector=>page.waitForFunction(s=>!document.querySelector(s).disabled,selector);
  const nav=async(name)=>{await page.locator('[data-page="'+name+'"]').click();await visible('#page-'+name);};
  const shot=async(name)=>{if(artifacts)await page.screenshot({path:path.join(artifacts,name+'.png'),fullPage:true});};
  const noOverflow=async()=>assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'horizontal page overflow');
  const postClick=async(selector,endpoint)=>{
    const n=posts.length;
    const response=page.waitForResponse(r=>r.url().endsWith(endpoint)&&r.request().method()==='POST');
    await page.locator(selector).click();await response;await page.waitForFunction(()=>!pending&&!sitePending);
    assert.equal(posts[n].url,endpoint);return posts[n];
  };
  await page.goto(origin);await waitEnabled('#toggle');await page.waitForFunction(()=>!!siteState);
  await shot('mobile-home');await noOverflow();
  for(const name of ['subscriptions','apps','settings','home']){await nav(name);await noOverflow();}
  assert.equal(posts.length,0,'opening pages must never change router or subscriptions');
  assert.equal(await page.locator('#welcome').isHidden(),true,'working installations hide onboarding');

  // Drafts survive navigation and status polling; saving sends every group.
  await nav('apps');
  // Opening/cancelling the add form must not create an empty program or offer deletion.
  await page.locator('#site-add').click();await visible('#site-dialog');
  assert.equal(await page.locator('#site-dialog button').filter({hasText:'حذف'}).count(),0);
  await page.locator('#site-name').fill('برنامهٔ لغوشده');
  await page.locator('#site-domains').fill('cancelled.example');
  await shot('mobile-add-app');await noOverflow();
  await page.locator('#site-cancel').click();
  assert.equal(await page.locator('[data-site]').count(),originalSites.length);
  assert.equal(posts.length,0);
  const custom=page.locator('[data-site="custom-example"]');
  await custom.locator('[role=switch]').click();await custom.locator('summary').click();
  await custom.locator('textarea').fill('custom.example\nmedia.example\nextra.example');
  await nav('home');await page.evaluate(()=>status());await nav('apps');
  assert.equal(await custom.locator('textarea').inputValue(),'custom.example\nmedia.example\nextra.example');
  assert.equal(posts.length,0);
  await shot('mobile-apps-draft');
  const saved=await postClick('#sites-save','/api/sites/save');
  assert.equal(saved.body.items.length,originalSites.length);
  assert.deepEqual(saved.body.items[0],originalSites[0]);
  assert.deepEqual(saved.body.items[2],originalSites[2]);
  assert.equal(saved.body.items[1].note,'preserve unknown fields');
  assert.equal(sites.pending,true);
  assert.match(await page.locator('#sites-summary').textContent(),/هنوز اعمال نشده/);

  // Failed apply remains visibly pending, and retry never drops saved domains.
  failApply=true;await postClick('#sites-apply','/api/sites/apply');
  assert.match(await page.locator('#sites-state').textContent(),/روتر پاسخ نداد/);
  assert.match(await page.locator('#sites-summary').textContent(),/هنوز اعمال نشده/);
  assert.equal(await page.locator('#sites-apply').isEnabled(),true);
  failApply=false;await postClick('#sites-apply','/api/sites/apply');
  assert.equal(sites.items[1].domains.length,3);
  assert.match(await page.locator('#sites-summary').textContent(),/روی روتر اعمال شده/);

  // A failed save cannot progress to apply; the draft remains editable.
  await custom.locator('[role=switch]').click();failSave=true;let before=posts.length;
  await postClick('#sites-apply','/api/sites/save');
  assert.equal(posts.length,before+1);assert.match(await page.locator('#sites-summary').textContent(),/ذخیره نشده/);
  failSave=false;before=posts.length;await postClick('#sites-apply','/api/sites/save');
  assert.deepEqual(posts.slice(before).map(p=>p.url),['/api/sites/save','/api/sites/apply']);

  // Late reads cannot overwrite edits made while they are in flight.
  delaySites=250;const reload=page.evaluate(()=>loadSites());
  await custom.locator('[role=switch]').click();await reload;delaySites=0;
  assert.equal(await custom.locator('[role=switch]').getAttribute('aria-checked'),'true');
  await postClick('#sites-save','/api/sites/save');
  await postClick('#sites-apply','/api/sites/apply');

  const beforeAdd=clone(sites.items);before=posts.length;
  await page.locator('#site-add').click();await page.locator('#site-name').fill('برنامهٔ تازه');
  await page.locator('#site-domains').fill('new.example\nmedia.new.example');
  await page.locator('#site-subdomains').uncheck();await page.locator('#site-create').click();
  assert.equal(await page.locator('#site-dialog').isHidden(),true);
  assert.equal(posts.length,before,'confirming add only edits the draft');
  assert.equal(await page.locator('[data-site]').count(),beforeAdd.length+1);
  await postClick('#sites-apply','/api/sites/save');
  assert.deepEqual(sites.items.slice(0,-1),beforeAdd);
  assert.deepEqual(sites.items.at(-1).domains,['new.example','media.new.example']);
  assert.equal(sites.items.at(-1).subdomains,false);

  // Groups, search, real action payloads, and editing the intended subscription.
  await nav('subscriptions');await page.locator('[data-group="one"] .group-open').click();
  await page.locator('#server-sort').selectOption('latency');
  assert.equal(await page.locator('[data-group="one"] .server-card').first().getAttribute('data-server'),'b');
  await page.locator('#server-search').fill('Server B');
  assert.equal(await page.locator('.server-card:visible').count(),1);await page.locator('#server-search').fill('');
  await shot('mobile-subscriptions');await noOverflow();
  await postClick('[data-server="b"] .choose','/api/apply');assert.equal(state.selected,'Server B');assert.equal(state.automatic,false);
  await postClick('[data-server="b"] .server-actions button:first-child','/api/test');
  await postClick('[data-server="b"] .server-actions button:nth-child(2)','/api/speed');
  await postClick('[data-group="one"] .group-tools button:first-child','/api/test');
  await postClick('[data-group="one"] .group-tools button:nth-child(2)','/api/update');
  await page.locator('[data-group="one"] .group-tools button:nth-child(3)').click();await visible('#import-dialog');
  await page.locator('#groupname').fill('اشتراک ویرایش‌شده');await page.locator('#input').fill('https://subscription.example/new');
  const edit=await postClick('#import','/api/import');assert.equal(edit.body.group,'one');assert.equal(state.groups.length,2);
  await page.locator('#add-subscription').click();await page.locator('#groupname').fill('اشتراک تازه');await page.locator('#input').fill('https://subscription.example/test');
  const added=await postClick('#import','/api/import');assert.equal(added.body.group,'');assert.equal(state.groups.length,3);
  await postClick('[data-group="new"] .group-tools button:nth-child(4)','/api/delete');
  await nav('settings');await page.locator('summary').filter({hasText:'اشتراک‌های حذف‌شده'}).click();
  await postClick('#trash button','/api/restore');assert.equal(state.groups.length,3);
  await postClick('#auto','/api/automatic');assert.equal(state.automatic,true);
  await postClick('#setup-check','/api/setup/check');await visible('#setup-result');
  await shot('mobile-settings');
  await nav('home');await postClick('#toggle','/api/toggle');assert.equal(state.enabled,false);
  await postClick('#toggle','/api/toggle');assert.equal(state.enabled,true);
  await postClick('#recover','/api/recover');
  // Hash bookmarks and phone/desktop layouts do not mutate stored settings.
  const last=posts.length;
  for(const width of [320,390,768,1280]){
    await page.setViewportSize({width,height:900});
    for(const name of ['home','subscriptions','apps','settings']){await nav(name);await noOverflow();}
    if(width<=780)assert.equal(await page.locator('.site-bar').evaluate(e=>getComputedStyle(e).position),'static','mobile save controls must not cover content');
  }
  await page.goto(origin+'/#subscriptions');await waitEnabled('#add-subscription');await visible('#page-subscriptions');
  assert.equal(posts.length,last);
  await page.locator('[data-group="one"] .group-open').click();await shot('desktop-subscriptions');
  await nav('home');await shot('desktop-home');
  // Error states disable unsafe actions, never fabricate a successful save.
  failSites=true;await page.reload();await page.waitForFunction(()=>!!siteError);
  await nav('apps');assert.equal(await page.locator('#sites-apply').isDisabled(),true);
  assert.deepEqual(errors,[]);
  console.log('Panel UI passed: four views, mobile widths, domain preservation, save/apply failures, subscription actions, and Xray controls.');
}finally{
  if(browser)await browser.close();await new Promise(resolve=>server.close(resolve));
}
