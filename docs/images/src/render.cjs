// Renders the README images from HTML, and the demo GIF from the real terminal output in captures/.
// Usage: NODE_PATH=<a node_modules with playwright> node docs/images/src/render.cjs   (needs ffmpeg for the GIF)
const { chromium } = require('playwright');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const OUT = path.resolve(__dirname, '..');
const CAP = path.join(__dirname, 'captures');
const VERSION = fs.readFileSync(path.join(CAP, 'version.txt'), 'utf8').trim().split(' · ')[0];
const FONTS = `<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600&family=Space+Grotesk:wght@500;700&display=swap" rel="stylesheet">`;
const C = { ink: '#0A0E1A', ink2: '#141A2B', line: '#2A3147', paper: '#F5F3EE', mist: '#E8E5DE', slate: '#8B93A7',
            green: '#D4FF4F', amber: '#FFC857', red: '#FF6B6B' };
const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

// --- Terminal ------------------------------------------------------------------------------------------------
function colorLine(l) {
  if (l.startsWith('$ ')) return `<span class="p">$</span> <span class="c">${esc(l.slice(2))}</span>`;
  // hermes airlock demo: "user    …", "agent   …", "  call  …", "  →     VERDICT  reason", "result  …"
  let m = l.match(/^(user|agent|result)(\s+)(.*)$/);
  if (m) return `<span class="k">${m[1]}${m[2]}</span><span class="${m[1] === 'result' ? 'green' : 'say'}">${esc(m[3])}</span>`;
  m = l.match(/^(\s+call\s+)(\S+)(.*)$/);
  if (m) return `<span class="k">${esc(m[1])}</span><span class="call">${esc(m[2])}</span><span class="v">${esc(m[3])}</span>`;
  m = l.match(/^(\s+→\s+)(BLOCK|ASKS YOU|allow)(.*)$/);
  if (m) {
    const cls = m[2] === 'BLOCK' ? 'red' : m[2] === 'ASKS YOU' ? 'amber' : 'green';
    const rest = esc(m[3]).replace(/· the conversation is now sealed/, '<span class="amber">· the conversation is now sealed</span>');
    return `<span class="k">${esc(m[1])}</span><span class="${cls}">${m[2]}</span><span class="v">${rest}</span>`;
  }
  m = l.match(/^(\w+)(\s*):\s(.*)$/);
  if (!m) return esc(l);
  const [, key, pad, val] = m;
  let cls = 'v';
  if (key === 'verdict') cls = val.startsWith('block') ? 'red' : val.startsWith('approve') ? 'amber' : 'green';
  if (key === 'agent' || key === 'user') cls = 'say';
  if (key === 'call') cls = 'call';
  if (key === 'result') cls = 'green';
  if (key === 'rule' || key === 'category' || key === 'taints') cls = 'dim';
  return `<span class="k">${esc(key + pad)} :</span> <span class="${cls}">${esc(val)}</span>`;
}
const TERM_CSS = `
.term{background:${C.ink};border-radius:4px;overflow:hidden;box-shadow:0 1px 0 ${C.line} inset}
.bar{background:${C.mist};color:${C.ink};font:500 13px Inter,sans-serif;padding:9px 14px;display:flex;gap:7px;align-items:center}
.bar i{width:10px;height:10px;border-radius:2px;background:${C.ink};opacity:.22;display:inline-block}
.bar b{margin-left:8px;font-weight:500}
pre{margin:0;padding:18px 20px;color:${C.paper};font:400 14px/1.6 'JetBrains Mono',monospace;white-space:pre-wrap;word-break:break-word}
pre .l{display:block;padding-left:11ch;text-indent:-11ch;min-height:1.6em}
.p{color:${C.green};font-weight:700}.c{color:${C.green}}.k{color:${C.slate}}.v{color:${C.paper}}
.green{color:${C.green};font-weight:700}.amber{color:${C.amber};font-weight:700}.red{color:${C.red};font-weight:700}
.say{color:${C.mist};font-style:italic}.call{color:${C.paper};font-weight:500}.dim{color:${C.slate}}
.cur{display:inline-block;width:8px;height:16px;background:${C.green};vertical-align:-3px}`;
function terminal(title, lines, width, screenHeight = 0) {
  // screenHeight: a fixed screen scrolled to its last line, like a terminal.
  const screen = screenHeight ? `<div class="screen" style="height:${screenHeight}px;overflow:hidden"><pre>${lines}</pre></div>`
    : `<pre>${lines}</pre>`;
  return `<!doctype html><html><head><meta charset="utf-8">${FONTS}<style>
body{margin:0;padding:0;background:transparent}${TERM_CSS}</style></head><body>
<div class="term" style="width:${width}px"><div class="bar"><i></i><i></i><i></i><b>${esc(title)}</b></div>
${screen}</div></body></html>`;
}

// --- Banner and social preview -------------------------------------------------------------------------------
function chamber(scale = 1) {
  // An airlock seen from above: untrusted content comes in on the left, the outer door is sealed until you approve.
  return `<svg width="${580 * scale}" height="${250 * scale}" viewBox="0 0 580 250" xmlns="http://www.w3.org/2000/svg"
  font-family="JetBrains Mono, monospace">
  <rect x="150" y="40" width="260" height="170" rx="3" fill="${C.ink2}" stroke="${C.line}" stroke-width="2"/>
  <rect x="146" y="40" width="8" height="170" fill="${C.slate}"/>
  <rect x="406" y="40" width="8" height="170" fill="${C.amber}"/>
  <text x="280" y="72" fill="${C.slate}" font-size="14" text-anchor="middle" letter-spacing="2">CONVERSATION</text>
  <text x="280" y="110" fill="${C.paper}" font-size="17" text-anchor="middle">read · search</text>
  <text x="280" y="134" fill="${C.paper}" font-size="17" text-anchor="middle">draft · write · run</text>
  <text x="280" y="178" fill="${C.green}" font-size="15" text-anchor="middle">free</text>
  <g font-size="14" fill="${C.slate}" text-anchor="end">
    <text x="96" y="86">web page</text><text x="96" y="128">email</text><text x="96" y="170">MCP output</text>
  </g>
  <g stroke="${C.slate}" stroke-width="1.5" fill="none">
    <path d="M104 82 H138"/><path d="M104 124 H138"/><path d="M104 166 H138"/>
  </g>
  <g fill="${C.slate}"><path d="M138 78 l8 4 -8 4z"/><path d="M138 120 l8 4 -8 4z"/><path d="M138 162 l8 4 -8 4z"/></g>
  <path d="M422 125 H454" stroke="${C.amber}" stroke-width="1.5" stroke-dasharray="4 4"/>
  <g transform="translate(460 108)">
    <rect x="0" y="12" width="26" height="22" rx="2" fill="${C.amber}"/>
    <path d="M5 12 V7 a8 8 0 0 1 16 0 V12" stroke="${C.amber}" stroke-width="3" fill="none"/>
  </g>
  <g font-size="14" fill="${C.amber}"><text x="432" y="176">messages · pushes</text><text x="432" y="194">uploads · memory</text></g>
  <text x="432" y="216" font-size="14" fill="${C.paper}">wait for you</text>
</svg>`;
}
function banner(w, h, big) {
  return `<!doctype html><html><head><meta charset="utf-8">${FONTS}<style>
body{margin:0;width:${w}px;height:${h}px;background:${C.ink};color:${C.paper};font-family:Inter,sans-serif;overflow:hidden;
display:flex;align-items:center;justify-content:space-between;padding:0 ${big ? 80 : 64}px;box-sizing:border-box;
background-image:linear-gradient(${C.ink2} 1px,transparent 1px),linear-gradient(90deg,${C.ink2} 1px,transparent 1px);
background-size:32px 32px}
.left{max-width:${big ? 560 : 600}px}
.kicker{font:500 13px 'JetBrains Mono',monospace;color:${C.green};letter-spacing:.14em;text-transform:uppercase}
h1{font:700 ${big ? 104 : 92}px/1 'Space Grotesk',sans-serif;margin:14px 0 18px;letter-spacing:-.03em}
p{font:400 ${big ? 25 : 23}px/1.4 Inter,sans-serif;color:${C.mist};margin:0}
.foot{margin-top:26px;font:400 13px 'JetBrains Mono',monospace;color:${C.slate}}
</style></head><body><div class="left"><div class="kicker">guardrails for Hermes Agent</div><h1>airlock</h1>
<p>Once a conversation reads something untrusted, nothing leaves without you.</p>
<div class="foot">local · no LLM call · fail-closed · Apache-2.0</div></div>${chamber(big ? 1.05 : 1)}</body></html>`;
}

// --- How it works --------------------------------------------------------------------------------------------
function howItWorks() {
  const row = (label, verdict, cls) =>
    `<div class="row"><span>${label}</span><span class="${cls}">${verdict}</span></div>`;
  return `<!doctype html><html><head><meta charset="utf-8">${FONTS}<style>
body{margin:0;width:1200px;background:${C.paper};color:${C.ink};font-family:Inter,sans-serif;padding:40px 40px 44px;box-sizing:border-box}
h2{font:700 34px 'Space Grotesk',sans-serif;margin:0 0 6px;letter-spacing:-.01em}
.sub{color:#4A5168;font-size:18px;margin:0 0 40px}
.flow{display:grid;grid-template-columns:1fr 150px 1fr;align-items:stretch}
.card{border:2px solid ${C.ink};border-radius:4px;background:#fff;padding:24px 24px}
.card.sealed{background:${C.ink};color:${C.paper}}
.tag{font:500 14px 'JetBrains Mono',monospace;letter-spacing:.12em;text-transform:uppercase;color:#4A5168}
.sealed .tag{color:${C.amber}}
h3{font:700 28px 'Space Grotesk',sans-serif;margin:8px 0 16px}
.row{display:flex;justify-content:space-between;gap:12px;font:400 18px/1.2 'JetBrains Mono',monospace;padding:12px 0;border-top:1px solid #E1DDD3}
.sealed .row{border-top-color:${C.line}}
.free{color:#3E7A00;font-weight:700}.sealed .free{color:${C.green}}
.ask{color:#B26A00;font-weight:700}.sealed .ask{color:${C.amber}}
.mid{display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:0 14px}
.mid .arrow{font:700 40px 'Space Grotesk';line-height:1}
.mid p{font:600 16px/1.4 Inter;margin:10px 0 0;color:${C.ink}}
.mid b{display:block;font:500 14px 'JetBrains Mono',monospace;color:#4A5168;margin-top:10px;line-height:1.7}
.band{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-top:20px}
.box{border:2px solid ${C.ink};border-radius:4px;padding:20px 22px;background:#fff}
.box .tag{color:#B3261E}.box.inh .tag{color:#4A5168}
.box h4{font:700 21px 'Space Grotesk';margin:8px 0 8px}.box p{margin:0;font-size:17px;line-height:1.5;color:#2B3145}
.block{color:#B3261E;font-weight:700}
</style></head><body>
<div class="flow">
  <div class="card"><div class="tag">clean conversation</div><h3>Work as usual</h3>
    ${row('read · write · run', 'free', 'free')}
    ${row('memory · skills · cron', 'logged', 'free')}
    ${row('browser · delegation', 'free', 'free')}
    ${row('push · message · upload', 'asks you', 'ask')}
  </div>
  <div class="mid"><div class="arrow">→</div><p>reads something untrusted</p>
    <b>web page<br>email<br>MCP output<br>git clone<br>customer</b></div>
  <div class="card sealed"><div class="tag">sealed conversation</div><h3>Nothing leaves without you</h3>
    ${row('read · search · draft', 'free', 'free')}
    ${row('memory · skills · cron', 'asks you', 'ask')}
    ${row('browser · delegation', 'asks you', 'ask')}
    ${row('push · message · data in URL', 'asks you', 'ask')}
  </div>
</div>
<div class="band">
  <div class="box"><div class="tag">walls · always</div><h4>Blocked in every conversation</h4>
    <p>Credentials and keys, the guard and Hermes's configuration, startup files, other profiles. <span class="block">block</span></p></div>
  <div class="box"><div class="tag">bypass · always</div><h4>Commands that hide what they run</h4>
    <p><code>eval</code>, <code>base64 -d | sh</code>, <code>curl | bash</code>, <code>$G push</code>: refused until written in clear. <span class="block">block</span></p></div>
  <div class="box inh"><div class="tag">around it</div><h4>Seals travel, tools are vetted</h4>
    <p>Subagents inherit the seal. Plugin and MCP tools need approval until you admit them. A crash blocks the call.</p></div>
</div></body></html>`;
}

// --- Demo GIF ------------------------------------------------------------------------------------------------
async function demoGif(page) {
  const lines = fs.readFileSync(path.join(CAP, 'demo.txt'), 'utf8').replace(/\s+$/, '').split('\n');
  const frames = [];          // [html lines, seconds]
  const cmd = lines[0].slice(2);
  for (let i = 1; i <= cmd.length; i++) frames.push([[`$ ${cmd.slice(0, i)}`], i === cmd.length ? 0.6 : 0.06]);
  for (let n = 2; n <= lines.length; n++) {
    const l = lines[n - 1];
    const hold = l.startsWith('verdict') ? 1.1 : l.startsWith('call') ? 0.55 : l.startsWith('agent') ? 0.5 : l === '' ? 0.12 : 0.22;
    frames.push([lines.slice(0, n), n === lines.length ? 4.5 : hold]);
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'airlock-gif-'));
  const list = [];
  for (let f = 0; f < frames.length; f++) {
    const [shown, secs] = frames[f];
    const body = shown.map(l => `<span class="l">${colorLine(l)}</span>`).join('') + (secs >= 0.5 || f === frames.length - 1 ? '' : '<span class="cur"></span>');
    await page.setContent(terminal(`hermes airlock demo · ${VERSION}, official Docker image`, body, 1060, 560));
    await page.evaluate(async () => { await document.fonts.ready; const s = document.querySelector('.screen');
      s.scrollTop = s.scrollHeight; });
    const file = path.join(dir, `f${String(f).padStart(4, '0')}.png`);
    await page.locator('.term').screenshot({ path: file });
    list.push(`file '${file}'\nduration ${secs}`);
  }
  list.push(`file '${path.join(dir, `f${String(frames.length - 1).padStart(4, '0')}.png`)}'`);
  fs.writeFileSync(path.join(dir, 'list.txt'), list.join('\n'));
  const pal = path.join(dir, 'pal.png');
  const gif = path.join(OUT, 'demo.gif');
  execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'concat', '-safe', '0', '-i', path.join(dir, 'list.txt'),
    '-vf', 'scale=960:-1:flags=lanczos,palettegen=max_colors=96:stats_mode=diff', pal]);
  execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'concat', '-safe', '0', '-i', path.join(dir, 'list.txt'),
    '-i', pal, '-lavfi', 'scale=960:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=none:diff_mode=rectangle', gif]);
  fs.rmSync(dir, { recursive: true, force: true });
  return gif;
}

// --- Live session GIF (a real Hermes session, recorded by session/record.py, framed by session/cast_frames.py) -----
async function liveGif(page) {
  const src = path.join(__dirname, 'session', 'frames.json');
  if (!fs.existsSync(src)) return null;
  const { frames, width } = JSON.parse(fs.readFileSync(src, 'utf8'));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'airlock-live-'));
  const list = [];
  for (let f = 0; f < frames.length; f++) {
    const [body, secs] = frames[f];
    await page.setContent(`<!doctype html><html><head><meta charset="utf-8">${FONTS}<style>
body{margin:0;background:transparent}${TERM_CSS}
pre{font:400 14.3px/1.42 'JetBrains Mono',monospace;color:${C.paper};white-space:pre;padding:14px 18px}</style></head><body>
<div class="term" style="width:${Math.ceil(width * 8.6 + 36)}px"><div class="bar"><i></i><i></i><i></i>
<b>Live session · Hermes Agent dev build · airlock · claude-haiku-5-5 · recorded, not simulated</b></div><pre>${body}</pre></div></body></html>`);
    await page.evaluate(() => document.fonts.ready);
    const file = path.join(dir, `f${String(f).padStart(4, '0')}.png`);
    await page.locator('.term').screenshot({ path: file });
    list.push(`file '${file}'\nduration ${secs}`);
  }
  list.push(`file '${path.join(dir, `f${String(frames.length - 1).padStart(4, '0')}.png`)}'`);
  fs.writeFileSync(path.join(dir, 'list.txt'), list.join('\n'));
  const pal = path.join(dir, 'pal.png');
  const gif = path.join(OUT, 'live-session.gif');
  execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'concat', '-safe', '0', '-i', path.join(dir, 'list.txt'),
    '-vf', 'scale=960:-1:flags=lanczos,palettegen=max_colors=96:stats_mode=diff', pal]);
  execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'concat', '-safe', '0', '-i', path.join(dir, 'list.txt'),
    '-i', pal, '-lavfi', 'scale=960:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=none:diff_mode=rectangle', gif]);
  fs.rmSync(dir, { recursive: true, force: true });
  return gif;
}

(async () => {
  const browser = await chromium.launch();
  const shot = async (html, file, viewport, selector = 'body', scale = 2) => {
    const page = await browser.newPage({ deviceScaleFactor: scale, viewport });
    await page.setContent(html);
    await page.evaluate(() => document.fonts.ready);
    await page.locator(selector).screenshot({ path: path.join(OUT, file) });
    await page.close();
    console.log(`docs/images/${file}`);
  };
  await shot(banner(1280, 400, false), 'banner.png', { width: 1280, height: 400 });
  await shot(banner(1280, 640, true), 'social-preview.png', { width: 1280, height: 640 }, 'body', 1);
  await shot(howItWorks(), 'how-it-works.png', { width: 1200, height: 700 });
  const check = fs.readFileSync(path.join(CAP, 'check.txt'), 'utf8').replace(/\s+$/, '').split('\n').map(l => `<span class="l">${colorLine(l)}</span>`).join('');
  await shot(terminal(`hermes airlock check · ${VERSION}, official Docker image`, check, 1060), 'check.png',
    { width: 1100, height: 800 }, '.term');
  const page = await browser.newPage({ deviceScaleFactor: 1, viewport: { width: 1100, height: 800 } });
  console.log(path.relative(path.resolve(OUT, '..', '..'), await demoGif(page)));
  const live = await liveGif(page);
  if (live) console.log(path.relative(path.resolve(OUT, '..', '..'), live));
  await browser.close();
})();
