#!/usr/bin/env node
/*
 * JsReplay.js — Level-2 companion to BshSandbox.java.
 *
 * BshSandbox replays the BeanShell layer but its stub WebView only LOGS loadUrl(); the
 * JavaScript the scripts inject (`wind.loadUrl("javascript: …")`) — the part that actually
 * runs in the on-device WebView against advertiser pages, with the GAD JS bridge — is never
 * executed. This harness closes that gap: it extracts every injected JS blob from the captured
 * .bsh scripts and runs it in a Node `vm` context under a mock DOM + a GAD bridge, with EVERY
 * dangerous global trapped (fetch/XHR/WebSocket/navigator/location/cookie/storage/eval/Function)
 * and every DOM node method trapped. No live site is contacted (all data is the mock DOM).
 *
 * Goal: decide, per script, whether the injected JS only OBSERVES (read XPath + report via the
 * bridge) or ACTS (synthetic .click()/dispatchEvent = engagement fraud, form submit, exfil,
 * cookie/session read, nested eval). Danger events are prefixed "!!".
 *
 * usage: node JsReplay.js <dir-of-bsh>   # prints corpus summary; writes <dir>/../js-replay/<name>.json
 */
'use strict';
const fs = require('fs'), path = require('path'), vm = require('vm');

// ---- extract loadUrl(...) arguments (paren/quote-aware char scan) ----
function argAt(text, openIdx) {
  let depth = 0, inStr = false, q = 0, esc = false;
  for (let i = openIdx; i < text.length; i++) {
    const c = text[i];
    if (inStr) { if (esc) esc = false; else if (c === '\\') esc = true; else if (c === q) inStr = false; continue; }
    if (c === '"' || c === "'") { inStr = true; q = c; continue; }
    if (c === '(') depth++;
    else if (c === ')') { depth--; if (depth === 0) return text.slice(openIdx + 1, i); }
  }
  return null;
}
// reconstruct the concatenated JS/URL from a Java string-concat expression.
function reconstruct(arg) {
  let out = '', inStr = false, q = 0, esc = false, lit = '', expr = '';
  const UN = { n: '\n', t: '\t', r: '\r', '"': '"', "'": "'", '\\': '\\' };
  for (let i = 0; i < arg.length; i++) {
    const c = arg[i];
    if (inStr) {
      if (esc) { lit += (UN[c] !== undefined ? UN[c] : c); esc = false; }
      else if (c === '\\') esc = true;
      else if (c === q) { inStr = false; out += lit; lit = ''; }
      else lit += c;
      continue;
    }
    if (c === '"' || c === "'") { if (expr.replace(/[\s+,]/g, '') !== '') out += '_P'; expr = ''; inStr = true; q = c; continue; }
    expr += c;
  }
  return out;
}
function extractInjections(src) {
  const out = [];
  let idx = 0;
  while ((idx = src.indexOf('loadUrl(', idx)) !== -1) {
    const open = src.indexOf('(', idx);
    const arg = argAt(src, open);
    idx = open + 1;
    if (arg == null) continue;
    const js = reconstruct(arg);
    if (/^\s*javascript:/i.test(js)) out.push({ kind: 'js', body: js.replace(/^\s*javascript:/i, '') });
    else { const m = js.match(/https?:\/\/[^\s"')]+|_P/); out.push({ kind: 'nav', body: (m ? m[0] : js).slice(0, 120) }); }
  }
  // also evaluateJavascript(...) if present
  let j = 0;
  while ((j = src.indexOf('evaluateJavascript(', j)) !== -1) {
    const open = src.indexOf('(', j); const arg = argAt(src, open); j = open + 1;
    if (arg) out.push({ kind: 'js', body: reconstruct(arg) });
  }
  return out;
}

// ---- instrumented JS runtime ----
function runJs(js) {
  const ev = [];
  const log = (t, d) => ev.push(t + ': ' + String(d).slice(0, 120));
  const danger = (t, d) => ev.push('!!' + t + ': ' + String(d).slice(0, 120));
  const sink = (name) => new Proxy(function () {}, {
    apply: (_t, _s, a) => { danger('SINK-CALL', name + '(' + a.map(x => String(x)).join(',').slice(0, 80) + ')'); return sink(name + '()'); },
    get: (_t, p) => { p = String(p); if (p === Symbol.toPrimitive || p === 'toString' || p === 'valueOf') return () => name; danger('SINK-GET', name + '.' + p); return sink(name + '.' + p); },
    set: (_t, p) => { danger('SINK-SET', name + '.' + String(p)); return true; },
  });
  const mkNode = (tag) => new Proxy({ tag, style: {} }, {
    get(o, p) { p = String(p);
      if (p === 'setAttribute') return (k, v) => log('DOM-MUT', tag + '.setAttribute(' + k + '=' + String(v).slice(0, 60) + ')');
      if (p === 'getAttribute') return (k) => { log('DOM-READ', tag + '.getAttribute(' + k + ')'); return ''; };
      if (p === 'click') return () => danger('SYNTH-CLICK', tag + '.click()');
      if (p === 'submit') return () => danger('FORM-SUBMIT', tag + '.submit()');
      if (p === 'dispatchEvent') return (e) => danger('SYNTH-DISPATCH', tag + '.dispatchEvent(' + (e && e.type) + ')');
      if (p === 'addEventListener') return (e) => log('DOM-LISTEN', tag + '.addEventListener(' + e + ') [attach only]');
      if (p === 'scrollIntoViewIfNeeded' || p === 'scrollIntoView') return () => log('DOM-SCROLL', tag);
      if (p === 'remove') return () => log('DOM-REMOVE', tag);
      if (p === 'focus' || p === 'blur') return () => log('DOM-' + p.toUpperCase(), tag);
      if (p === 'getElementsByTagName' || p === 'getElementsByClassName') return (x) => { log('DOM-QUERY', tag + '.' + p + '(' + x + ')'); return [mkNode(tag + '>' + x)]; };
      if (p === 'querySelector') return (x) => { log('DOM-QS', x); return mkNode(x); };
      if (p === 'style') return o.style;
      if (p === 'parentNode' || p === 'parentElement' || p === 'firstChild' || p === 'nextElementSibling') return mkNode(tag + '.' + p);
      if (p === 'value' || p === 'innerText' || p === 'textContent' || p === 'innerHTML') { log('DOM-READ', tag + '.' + p); return ''; }
      if (p === 'href' || p === 'src') { log('DOM-READ', tag + '.' + p); return ''; }
      if (p in o) return o[p];
      return mkNode(tag + '.' + p);
    },
    set(o, p, v) { p = String(p);
      if (p === 'onclick' || p === 'onload') log('DOM-HANDLER-SET', tag + '.' + p + ' (handler attached; not a click)');
      else if (p === 'innerHTML') danger('DOM-INNERHTML-WRITE', tag + ' = ' + String(v).slice(0, 60));
      else if (p === 'src' || p === 'href') log('DOM-NAV-SET', tag + '.' + p + '=' + String(v).slice(0, 60));
      else log('DOM-SET', tag + '.' + p);
      o[p] = v; return true;
    },
  });
  const xr = () => ({ numberValue: 1, booleanValue: true, stringValue: '_v', singleNodeValue: mkNode('xnode'),
    snapshotLength: 1, snapshotItem: () => mkNode('xnode'), iterateNext: (() => { let n = 0; return () => (n++ ? null : mkNode('xnode')); })() });
  const documentMock = new Proxy({ body: mkNode('body'), documentElement: mkNode('html') }, {
    get(o, p) { p = String(p);
      if (p === 'evaluate') return (x) => { log('XPATH', x); return xr(); };
      if (p === 'getElementById') return (id) => { log('DOM-GETID', id); return mkNode('#' + id); };
      if (p === 'querySelector') return (s) => { log('DOM-QS', s); return mkNode(s); };
      if (p === 'querySelectorAll') return (s) => { log('DOM-QSALL', s); return [mkNode(s)]; };
      if (p === 'getElementsByClassName') return (c) => { log('DOM-GETCLASS', c); return [mkNode(c)]; };
      if (p === 'getElementsByTagName') return (t) => { log('DOM-GETTAG', t); return [mkNode(t)]; };
      if (p === 'createElement') return (t) => { log('DOM-CREATE', t); return mkNode(t); };
      if (p === 'cookie') { danger('COOKIE-READ', 'document.cookie'); return ''; }
      if (p === 'location') return sink('document.location');
      if (p in o) return o[p];
      return mkNode('document.' + p);
    },
    set(o, p, v) { p = String(p); if (p === 'cookie') danger('COOKIE-WRITE', String(v).slice(0, 60)); o[p] = v; return true; },
  });
  const GAD = new Proxy({}, { get: (_t, p) => (...a) => log('BRIDGE', 'GAD.' + String(p) + '(' + a.map(x => String(x)).join(',').slice(0, 70) + ')') });
  const XPathResult = { ANY_TYPE: 0, NUMBER_TYPE: 1, STRING_TYPE: 2, BOOLEAN_TYPE: 3, UNORDERED_NODE_ITERATOR_TYPE: 4,
    ORDERED_NODE_ITERATOR_TYPE: 5, UNORDERED_NODE_SNAPSHOT_TYPE: 6, ORDERED_NODE_SNAPSHOT_TYPE: 7,
    ANY_UNORDERED_NODE_TYPE: 8, FIRST_ORDERED_NODE_TYPE: 9 };
  const sandbox = {
    _P: '_P', document: documentMock, GAD, XPathResult,
    console: { log: (...a) => log('console', a.join(' ')), error: () => {}, warn: () => {} },
    setTimeout: (f, t) => { log('setTimeout', t); try { if (typeof f === 'function') f(); } catch (e) {} return 0; },
    setInterval: (f, t) => { log('setInterval', t); return 0; }, clearTimeout: () => {}, clearInterval: () => {},
    handler: { postDelayed: (f, t) => { log('postDelayed', t); try { if (typeof f === 'function') f(); } catch (e) {} }, post: (f) => { try { if (typeof f === 'function') f(); } catch (e) {} } },
    alert: (m) => log('alert', m), fetch: sink('fetch'), XMLHttpRequest: function () { return sink('XMLHttpRequest'); },
    WebSocket: function () { return sink('WebSocket'); }, EventSource: function () { return sink('EventSource'); },
    navigator: sink('navigator'), localStorage: sink('localStorage'), sessionStorage: sink('sessionStorage'),
    indexedDB: sink('indexedDB'), eval: sink('eval'), Function: sink('Function'), importScripts: sink('importScripts'),
    Image: function () { return sink('Image'); }, atob: (s) => String(s), btoa: (s) => String(s),
  };
  sandbox.window = sandbox; sandbox.self = sandbox; sandbox.globalThis = sandbox; sandbox.top = sandbox;
  const locProxy = sink('location'); sandbox.location = locProxy;
  const ctx = vm.createContext(sandbox);
  try { vm.runInContext(js, ctx, { timeout: 2000 }); }
  catch (e) { log('JS-ERR', (e && e.message) || e); }
  return ev;
}

// ---- driver ----
const dir = process.argv[2];
if (!dir) { console.error('usage: node JsReplay.js <dir-of-bsh>'); process.exit(2); }
const outDir = path.join(dir, '..', 'js-replay');
fs.mkdirSync(outDir, { recursive: true });
const files = fs.readdirSync(dir).filter(f => f.endsWith('.bsh')).sort();
const agg = { files: 0, withJs: 0, injections: 0, danger: {}, navHosts: {}, bridgeCalls: {}, domMut: 0, xpath: 0, listen: 0 };
const dangerFiles = [];
for (const f of files) {
  const src = fs.readFileSync(path.join(dir, f), 'utf8');
  const inj = extractInjections(src);
  const js = inj.filter(x => x.kind === 'js');
  const navs = inj.filter(x => x.kind === 'nav');
  agg.files++; agg.injections += js.length; if (js.length) agg.withJs++;
  const events = [];
  for (const b of js) events.push(...runJs(b.body));
  const dangers = events.filter(e => e.startsWith('!!'));
  for (const e of events) {
    if (e.startsWith('!!')) { const k = e.slice(2).split(':')[0]; agg.danger[k] = (agg.danger[k] || 0) + 1; }
    if (e.startsWith('XPATH')) agg.xpath++;
    if (e.startsWith('DOM-MUT')) agg.domMut++;
    if (e.startsWith('DOM-LISTEN')) agg.listen++;
    if (e.startsWith('BRIDGE')) { const m = e.match(/GAD\.(\w+)/); if (m) agg.bridgeCalls[m[1]] = (agg.bridgeCalls[m[1]] || 0) + 1; }
  }
  for (const n of navs) { const h = (n.body.match(/https?:\/\/([^/]+)/) || [, n.body])[1]; agg.navHosts[h] = (agg.navHosts[h] || 0) + 1; }
  if (dangers.length) dangerFiles.push({ f, dangers });
  fs.writeFileSync(path.join(outDir, f.replace('.bsh', '.json')), JSON.stringify({ file: f, js_injections: js.length, navigations: navs.map(n => n.body), events }, null, 1));
}
console.log('=== JS-layer replay summary (' + agg.files + ' scripts, ' + agg.withJs + ' inject JS, ' + agg.injections + ' JS blobs) ===');
console.log('XPATH reads: ' + agg.xpath + ' | DOM mutations (style/blur/border): ' + agg.domMut + ' | event listeners attached: ' + agg.listen);
console.log('GAD bridge calls: ' + JSON.stringify(agg.bridgeCalls));
console.log('Navigation hosts: ' + JSON.stringify(agg.navHosts));
console.log('\n!!! DANGER events (network/exec/cookie/synthetic-interaction/exfil): ' + JSON.stringify(agg.danger));
if (dangerFiles.length === 0) console.log('  => NONE across all scripts (observe-only: read XPath -> report via bridge; annotate DOM).');
else for (const d of dangerFiles) console.log('  ' + d.f + ': ' + d.dangers.join(' | '));
console.log('\nper-script JSON -> ' + outDir);
