import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import axios from 'axios';
import * as cheerio from 'cheerio';
import dns from 'node:dns/promises';
import net from 'node:net';
import {performance} from 'node:perf_hooks';
import {URL} from 'node:url';
import jsBeautify from 'js-beautify';
const { html: beautifyHtml } = jsBeautify;
import whois from 'whois-json';
import {parse as parseDomain} from 'tldts';

const app = express();
const PORT = process.env.PORT || 3000;
const cache = new Map();
const hits = new Map();

app.use(cors());
app.use(helmet({contentSecurityPolicy:false, crossOriginEmbedderPolicy:false}));
app.use(express.json({limit:'18mb'}));
app.use(express.static('public'));
app.use((req,res,next)=>{
  const ip=req.ip||req.socket.remoteAddress||'local';
  const now=Date.now(); const rec=hits.get(ip)||[]; const fresh=rec.filter(t=>now-t<60_000); fresh.push(now); hits.set(ip,fresh);
  if(fresh.length>90) return res.status(429).json({error:'طلبات كثيرة جدًا، انتظر دقيقة ثم حاول مجددًا'});
  next();
});

function okUrl(input){try{let s=String(input||'').trim(); if(!s) throw 0; if(!/^https?:\/\//i.test(s)) s='https://'+s; const u=new URL(s); if(!['http:','https:'].includes(u.protocol)) throw 0; return u;}catch{return null}}
function isPrivateIP(ip){return /^(10\.|127\.|0\.|169\.254\.|172\.(1[6-9]|2\d|3[0-1])\.|192\.168\.|::1|fc|fd|fe80)/i.test(ip)}
async function guardPublicHost(host){ if(['localhost','127.0.0.1','::1'].includes(host)) throw Error('لا يمكن فحص localhost'); const rows=await dns.lookup(host,{all:true}).catch(()=>[]); for(const r of rows){ if(net.isIP(r.address) && isPrivateIP(r.address)) throw Error('هذا العنوان داخلي أو خاص ولا يمكن فحصه للحماية'); }}
function abs(base,v){try{return new URL(v,base||'https://example.com/').href}catch{return v||''}}
function uniq(a){return [...new Set(a.filter(Boolean))]}
function text($,sel){return ($(sel).first().text()||'').trim().replace(/\s+/g,' ')}
function hostOf(x){try{return new URL(x).hostname}catch{return''}}

async function fetchPage(url){
  const key='fetch:'+url; const cached=cache.get(key); if(cached && Date.now()-cached.t<90_000) return cached.v;
  const u=new URL(url); await guardPublicHost(u.hostname);
  const t=performance.now();
  const res=await axios.get(url,{timeout:26000,maxRedirects:6,validateStatus:null,responseType:'text',maxContentLength:9_000_000,headers:{'User-Agent':'Mozilla/5.0 CodeScopeUltra/3.0 WebsiteAnalyzer','Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}});
  const out={html:String(res.data||''),status:res.status,headers:res.headers,finalUrl:res.request?.res?.responseUrl||url,ms:Math.round(performance.now()-t)};
  cache.set(key,{t:Date.now(),v:out}); return out;
}

function detectTech(html,$,headers){
  const bag=(html+'\n'+JSON.stringify(headers||{})).toLowerCase();
  const tests={
    WordPress:['wp-content','wp-includes','woocommerce'],Shopify:['cdn.shopify','shopify.theme'],Wix:['wixstatic','x-wix'],Webflow:['webflow.js','webflow.io'],Joomla:['joomla'],Drupal:['drupal'],Ghost:['ghost'],Magento:['mage/cookies','magento'],Laravel:['laravel_session'],Django:['csrftoken'],Rails:['csrf-param','csrf-token'],
    React:['react','data-reactroot','__next_data__'],NextJS:['__next_data__','/_next/static'],Vue:['vue.js','data-v-','__vue__'],Nuxt:['__nuxt__'],Angular:['ng-version','angular'],Svelte:['svelte'],Astro:['astro-island'],Alpine:['alpinejs'],
    jQuery:['jquery'],Bootstrap:['bootstrap'],Tailwind:['tailwind'],FontAwesome:['font-awesome','fontawesome'],GSAP:['gsap'],ThreeJS:['three.min.js'],Swiper:['swiper-bundle','swiper.min'],
    Cloudflare:['cloudflare','cf-ray'],Fastly:['fastly'],Akamai:['akamai'],CloudFront:['cloudfront'],BunnyCDN:['bunnycdn'],Vercel:['x-vercel','vercel'],Netlify:['netlify'],GoogleCloud:['google frontend'],
    GoogleAnalytics:['gtag(','google-analytics','g-'],GoogleTagManager:['googletagmanager'],AhrefsAnalytics:['analytics.ahrefs.com'],FacebookPixel:['fbq('],Hotjar:['hotjar'],MicrosoftClarity:['clarity.ms'],
    Stripe:['js.stripe.com'],PayPal:['paypal.com/sdk'],reCAPTCHA:['recaptcha'],hCaptcha:['hcaptcha'],SchemaOrg:['schema.org'],OpenGraph:['property="og:','property=\'og:'],
    Nginx:['nginx'],Apache:['apache'],Express:['x-powered-by":"express']
  };
  return Object.entries(tests).filter(([_,keys])=>keys.some(k=>bag.includes(k))).map(([name])=>({name,confidence:'high'}));
}
function lighthouseLike(r){
  const seo=Math.max(0,r.score); let sec=100; Object.values(r.security).forEach(v=>{if(!v) sec-=8}); sec=Math.max(0,sec);
  let access=100; if(r.imagesNoAlt) access-=Math.min(35,r.imagesNoAlt*5); if(!r.lang) access-=15; if(!r.hasLabels) access-=8; if((r.headings||[]).length===0) access-=10; access=Math.max(0,access);
  let perf=100; if(r.counts.htmlBytes>500000) perf-=18; if(r.counts.scripts>25) perf-=20; if(r.counts.styles>15) perf-=10; if((r.timing.fetchMs||0)>4000) perf-=22; if(r.counts.images>80) perf-=10;
  return {seo,security:sec,accessibility:access,performance:Math.max(0,perf),bestPractices:Math.round((sec+access)/2)};
}
function codeQuality(html,$){
  const qs=(s)=>$(s).length;
  return [
    {check:'DOCTYPE موجود',ok:/<!doctype html>/i.test(html.slice(0,400))},
    {check:'Viewport للموبايل',ok:qs('meta[name="viewport"]')>0},
    {check:'HTML lang موجود',ok:!!$('html').attr('lang')},
    {check:'لا توجد inline event handlers كثيرة',ok:(html.match(/\son\w+=/gi)||[]).length<8},
    {check:'استخدام alt للصور',ok:qs('img:not([alt])')===0},
    {check:'عدد H1 مناسب',ok:qs('h1')===1},
    {check:'النماذج تحتوي تسميات أو aria',ok:qs('input,textarea,select')===0 || qs('label,[aria-label],[aria-labelledby]')>0},
    {check:'لا توجد سكربتات كثيرة جدًا',ok:qs('script[src]')<=25}
  ];
}
function analyzeHtml(html,url='',headers={},timing={}){
  const $=cheerio.load(html,{decodeEntities:true});
  const title=text($,'title'); const desc=($('meta[name="description" i]').attr('content')||'').trim();
  const viewport=!!$('meta[name="viewport"]').length; const canonical=$('link[rel="canonical"]').attr('href')||''; const lang=$('html').attr('lang')||'';
  const hasLabels=$('label').length>0 || $('[aria-label],[aria-labelledby]').length>0;
  const headings=$('h1,h2,h3,h4,h5,h6').toArray().map(e=>({tag:e.tagName.toUpperCase(),text:$(e).text().trim().replace(/\s+/g,' ').slice(0,240)}));
  const meta=$('meta').toArray().map(m=>({name:$(m).attr('name')||$(m).attr('property')||$(m).attr('http-equiv')||'',content:($(m).attr('content')||'').slice(0,500)})).filter(x=>x.name||x.content);
  const links=$('a[href]').toArray().map(a=>{let href=abs(url,$(a).attr('href')); let external=null; try{external=url?new URL(href).host!==new URL(url).host:null}catch{} return {text:$(a).text().trim().replace(/\s+/g,' ').slice(0,140),href,external,rel:$(a).attr('rel')||''}});
  const images=$('img').toArray().map(i=>({src:abs(url,$(i).attr('src')||$(i).attr('data-src')||''),alt:$(i).attr('alt')||'',loading:$(i).attr('loading')||'',width:$(i).attr('width')||'',height:$(i).attr('height')||''}));
  const scripts=uniq($('script[src]').toArray().map(s=>abs(url,$(s).attr('src')))); const styles=uniq($('link[rel="stylesheet"]').toArray().map(s=>abs(url,$(s).attr('href'))));
  const urls=uniq([...html.matchAll(/https?:\/\/[^'"`\s<>\\)]+/g)].map(m=>m[0].replace(/[),.;]+$/,'')));
  const apis=urls.filter(x=>/api|graphql|socket|json|ajax|rest|endpoint|webhook|rpc/i.test(x)).slice(0,300);
  const domains=uniq([...links.map(l=>hostOf(l.href)),...scripts.map(hostOf),...styles.map(hostOf),...images.map(i=>hostOf(i.src)),...urls.map(hostOf)]).filter(Boolean).sort();
  const og=$('meta[property^="og:"],meta[name^="twitter:"]').toArray().map(m=>({name:$(m).attr('property')||$(m).attr('name'),content:$(m).attr('content')||''}));
  const structured=$('script[type="application/ld+json"]').toArray().map(s=>{try{return JSON.parse($(s).text())}catch{return{invalid:true,raw:$(s).text().slice(0,900)}}});
  const cookieHeader=headers['set-cookie']; const cookieArray=Array.isArray(cookieHeader)?cookieHeader:(cookieHeader?[String(cookieHeader)]:[]);
  const cookies=cookieArray.map(c=>({name:(c.match(/^([^=;]+)/)||[])[1]||'',secure:/;\s*secure/i.test(c),httpOnly:/;\s*httponly/i.test(c),sameSite:(c.match(/samesite=([^;]+)/i)||[])[1]||'',raw:c.slice(0,300)}));
  const security={https:url?url.startsWith('https://'):false,hsts:!!headers['strict-transport-security'],csp:!!headers['content-security-policy'],xFrameOptions:!!headers['x-frame-options'],xContentTypeOptions:!!headers['x-content-type-options'],referrerPolicy:!!headers['referrer-policy'],permissionsPolicy:!!headers['permissions-policy']};
  const cssText=$('style').toArray().map(s=>$(s).text()).join('\n'); const colors=uniq([...cssText.matchAll(/#[0-9a-f]{3,8}|rgba?\([^)]*\)|hsla?\([^)]*\)/gi)].map(x=>x[0])).slice(0,100);
  const forms=$('form').toArray().map(f=>({action:abs(url,$(f).attr('action')||''),method:($(f).attr('method')||'GET').toUpperCase(),inputs:$(f).find('input,textarea,select').length}));
  let score=100,alerts=[]; const warn=(msg,level='warn',pts=5)=>{alerts.push({msg,level}); score-=pts};
  if(!title)warn('لا يوجد title','bad',15); else if(title.length<20||title.length>65)warn('طول title غير مثالي','warn',5);
  if(!desc)warn('لا يوجد meta description','bad',15); else if(desc.length<70||desc.length>170)warn('طول description غير مثالي','warn',5);
  if(headings.filter(h=>h.tag==='H1').length!==1)warn('يفضل وجود H1 واحد فقط','warn',8); if(!viewport)warn('لا يوجد viewport للموبايل','bad',10); if(!canonical)warn('لا يوجد canonical','warn',4); if(!lang)warn('وسم html بدون lang','warn',5);
  const imagesNoAlt=images.filter(i=>!i.alt).length; if(imagesNoAlt)warn(`${imagesNoAlt} صورة بدون alt`,'warn',Math.min(14,imagesNoAlt*2));
  if(url&&url.startsWith('https://')&&!security.hsts)warn('لا يوجد HSTS Header','warn',6); if(url&&!security.csp)warn('لا يوجد Content-Security-Policy Header','warn',5);
  score=Math.max(0,Math.min(100,score));
  const base={url,title,description:desc,canonical,lang,score,alerts,counts:{htmlBytes:Buffer.byteLength(html),links:links.length,externalLinks:links.filter(l=>l.external).length,internalLinks:links.filter(l=>l.external===false).length,images:images.length,scripts:scripts.length,styles:styles.length,apis:apis.length,forms:forms.length},meta,headings,links:links.slice(0,1000),images:images.slice(0,1000),imagesNoAlt,resources:{scripts,styles,urls},domains,apis,forms,openGraph:og,structuredData:structured,technologies:detectTech(html,$,headers),security,cookies,css:{inlineBytes:cssText.length,colors},headers,timing,hasLabels,quality:codeQuality(html,$),sourcePreview:beautifyHtml(html,{indent_size:2}).slice(0,400000)};
  base.lighthouse=lighthouseLike(base); return base;
}

app.get('/health',(req,res)=>res.json({ok:true,name:'CodeScope Ultra',version:'3.0.0',arabicDefault:true}));
app.post('/api/analyze',async(req,res)=>{try{const u=okUrl(req.body.url); if(!u)return res.status(400).json({error:'رابط غير صحيح'}); const f=await fetchPage(u.href); res.json({ok:true,...analyzeHtml(f.html,f.finalUrl,f.headers,{fetchMs:f.ms,status:f.status})})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/analyze-html',(req,res)=>{try{const html=String(req.body.html||''); if(!html.trim()) return res.status(400).json({error:'أرسل كود HTML أولًا'}); res.json({ok:true,...analyzeHtml(html,req.body.url||'',{}, {})})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/diff',(req,res)=>{const a=beautifyHtml(String(req.body.a||'')).split('\n'),b=beautifyHtml(String(req.body.b||'')).split('\n');let added=0,removed=0,lines=[];for(let i=0;i<Math.max(a.length,b.length);i++){if(a[i]===b[i])lines.push({type:'same',text:a[i]||''});else{if(a[i]!=null){removed++;lines.push({type:'del',text:a[i]})}if(b[i]!=null){added++;lines.push({type:'add',text:b[i]})}}}res.json({ok:true,added,removed,lines:lines.slice(0,25000)})});
app.post('/api/dns',async(req,res)=>{try{const u=okUrl(req.body.url); if(!u)return res.status(400).json({error:'رابط غير صحيح'}); const host=u.hostname; await guardPublicHost(host); const out={host}; for(const t of ['A','AAAA','MX','TXT','NS','CNAME','CAA']){try{out[t]=await dns.resolve(host,t)}catch{out[t]=[]}} res.json({ok:true,...out})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/whois',async(req,res)=>{try{const u=okUrl(req.body.url); if(!u)return res.status(400).json({error:'رابط غير صحيح'}); const d=parseDomain(u.hostname).domain||u.hostname; const data=await whois(d,{timeout:14000}); res.json({ok:true,domain:d,data})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/robots-sitemap',async(req,res)=>{try{const u=okUrl(req.body.url); if(!u)return res.status(400).json({error:'رابط غير صحيح'}); await guardPublicHost(u.hostname); const origin=u.origin; const get=p=>axios.get(origin+p,{timeout:12000,validateStatus:null,responseType:'text'}).then(r=>({status:r.status,data:String(r.data||'').slice(0,300000)})).catch(e=>({status:0,error:e.message,data:''})); const robots=await get('/robots.txt'); const sitemapUrls=uniq([...(robots.data||'').matchAll(/^\s*Sitemap:\s*(\S+)/gim)].map(m=>m[1])); const sitemap=await get('/sitemap.xml'); res.json({ok:true,robots,sitemap,sitemapUrls})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/screenshot',async(req,res)=>{let browser;try{const u=okUrl(req.body.url); if(!u)return res.status(400).json({error:'رابط غير صحيح'}); await guardPublicHost(u.hostname); const {chromium}=await import('playwright'); browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage']}); const page=await browser.newPage({viewport:{width:1365,height:900},userAgent:'Mozilla/5.0 CodeScopeUltra Screenshot'}); await page.goto(u.href,{waitUntil:'networkidle',timeout:35000}); const title=await page.title(); const img=await page.screenshot({type:'png',fullPage:false}); await browser.close(); res.json({ok:true,title,url:u.href,image:'data:image/png;base64,'+img.toString('base64')})}catch(e){try{if(browser)await browser.close()}catch{} res.status(500).json({error:'ميزة Screenshot حقيقية وتحتاج Chromium في الاستضافة. ملف render.yaml مجهز لذلك، وإذا فشلت فالسبب من بيئة الاستضافة أو حماية الموقع. التفاصيل: '+e.message})}});

app.listen(PORT,()=>console.log('CodeScope Ultra v3 running on http://localhost:'+PORT));
