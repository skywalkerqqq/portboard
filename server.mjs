// Portboard v2 — 零依赖 Node 端口监控工作台 (Windows)
// 数据源: netstat -ano(主) / tasklist(进程名) / PowerShell CIM(路径与命令行，后台补全)
// 设计取舍见 README.md「数据源选型」：netstat ~100ms / tasklist ~350ms / PowerShell ~1.3s，
// 因此 netstat 走 1.2s TTL 快照 + 单飞(单飞合并并发)，进程表 20s TTL，CIM 走后台惰性补全。
import http from 'node:http';
import net from 'node:net';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execFileP = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VERSION = '2.0.0';
const PORT = Number(process.env.PORTBOARD_PORT || 8788);
const HOST = '127.0.0.1';
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, '.portboard');
const EVENT_LOG = path.join(DATA_DIR, 'events.jsonl');

// 每次启动随机生成，注入页面；所有写操作必须携带，抵御 CSRF / 恶意本地页面调用
const TOKEN = crypto.randomBytes(18).toString('base64url');
const STARTED_AT = Date.now();

const SNAPSHOT_TTL = clampNum(Number(process.env.PORTBOARD_TTL || 1200), 300, 30000);
const PROC_TTL = 20000;         // 进程名表：tasklist 350ms，没必要每轮都跑
const CIM_TTL = 120000;         // 可执行路径：PowerShell 1.3s，后台惰性补全
const EVENT_MAX = 800;
// Windows 动态端口区间：这一段的 UDP 端点会随系统服务频繁开关，属于噪声，
// 记入审计但不触发桌面告警（否则一晚上能刷几十条）。
const EPHEMERAL_MIN = 49152;

function clampNum(n, lo, hi) { return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : lo; }
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ---------- 子进程 ----------
function decode(buf) {
  try { return new TextDecoder('gbk').decode(buf); }
  catch { return Buffer.from(buf).toString('utf8'); }
}
async function run(file, args, timeout = 15000) {
  const { stdout } = await execFileP(file, args, {
    encoding: 'buffer', windowsHide: true, maxBuffer: 32 * 1024 * 1024, timeout,
  });
  return decode(stdout);
}
// 单飞：并发调用共享同一个 promise。原版用「全局串行队列」解决 netstat 互相干扰，
// 但串行会让每个请求都排一次队；单飞才是既安全又省资源的做法。
const single = (() => {
  const m = new Map();
  return {
    do(key, fn) {
      if (m.has(key)) return m.get(key);
      const p = Promise.resolve().then(fn).finally(() => m.delete(key));
      m.set(key, p);
      return p;
    },
  };
})();

// ---------- 端口/地址解析 ----------
const RE_TCP = /^\s*TCP\s+(\S+)\s+(\S+)\s+([A-Z_]+)\s+(\d+)\s*$/i;
const RE_UDP = /^\s*UDP\s+(\S+)\s+(\S+)\s+(\d+)\s*$/i;

function splitHP(s) {
  const i = s.lastIndexOf(':');
  if (i <= 0) return { host: s === '*' ? '*' : '', port: NaN };
  let host = s.slice(0, i);
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  return { host, port: Number(s.slice(i + 1)) };
}

// 原版 isWildcard 用 addr.slice(0, lastIndexOf(':'))，对 0.0.0.0（无冒号）返回 "0.0.0."，
// 于是所有 0.0.0.0 的监听口都被误判成「仅本机」——445/135 这类高危暴露口全部漏报。
const SCOPE_RANK = { loopback: 0, linklocal: 1, iface: 2, wildcard: 3 };
function classify(host) {
  if (!host || host === '*' || host === '0.0.0.0' || host === '::') return 'wildcard';
  if (host === '127.0.0.1' || host === '::1' || /^127\./.test(host)) return 'loopback';
  if (/^169\.254\./.test(host) || /^fe80:/i.test(host)) return 'linklocal';
  return 'iface';
}

const SERVICE_NAMES = {
  20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP',
  80: 'HTTP', 110: 'POP3', 135: 'MSRPC', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS',
  143: 'IMAP', 161: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
  514: 'Syslog', 587: 'SMTP', 631: 'IPP', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
  1433: 'MSSQL', 1521: 'Oracle', 1883: 'MQTT', 2049: 'NFS', 2375: 'Docker',
  2379: 'etcd', 3000: 'Dev Server', 3001: 'Dev Server', 3306: 'MySQL', 3389: 'RDP',
  4200: 'Angular', 5000: 'Dev Server', 5432: 'PostgreSQL', 5601: 'Kibana',
  5672: 'RabbitMQ', 5900: 'VNC', 6379: 'Redis', 7001: 'WebLogic', 7474: 'Neo4j',
  8000: 'Dev Server', 8080: 'HTTP-Alt', 8081: 'HTTP-Alt', 8086: 'InfluxDB',
  8443: 'HTTPS-Alt', 8888: 'Jupyter', 9000: 'PHP-FPM', 9090: 'Prometheus',
  9200: 'Elasticsearch', 11211: 'Memcached', 15672: 'RabbitMQ-Mgmt',
  27017: 'MongoDB', 5173: 'Vite', 5174: 'Vite', 5175: 'Vite', 4173: 'Vite-Preview',
};

// ---------- 采集：socket 表 ----------
async function scanSockets() {
  return single.do('sockets', async () => {
    const t0 = Date.now();
    let tcp = '', udp = '';
    // netstat 串行执行：Windows 下并发调用会出现输出截断（原版注释中的坑）
    try { tcp = await run('netstat', ['-ano', '-p', 'TCP']); } catch { /* 无匹配时返回非 0 */ }
    try { udp = await run('netstat', ['-ano', '-p', 'UDP']); } catch { /* 同上 */ }

    const sockets = [];
    for (const line of tcp.split(/\r?\n/)) {
      const m = RE_TCP.exec(line);
      if (!m) continue;
      const L = splitHP(m[1]), R = splitHP(m[2]);
      sockets.push({
        proto: 'TCP', localHost: L.host, localPort: L.port,
        remoteHost: R.host, remotePort: R.port,
        state: m[3].toUpperCase(), pid: Number(m[4]),
      });
    }
    for (const line of udp.split(/\r?\n/)) {
      const m = RE_UDP.exec(line);
      if (!m) continue;
      const L = splitHP(m[1]), R = splitHP(m[2]);
      sockets.push({
        proto: 'UDP', localHost: L.host, localPort: L.port,
        remoteHost: R.host, remotePort: R.port, state: 'UDP', pid: Number(m[3]),
      });
    }
    return { sockets, costMs: Date.now() - t0 };
  });
}

// ---------- 采集：进程表 ----------
const procMap = new Map(); // pid -> { name, mem, session }
let procAt = 0;
let lastForceProc = 0;
async function processTable(force = false) {
  if (!force && procAt && Date.now() - procAt < PROC_TTL) return procMap;
  return single.do('tasklist', async () => {
    if (!force && procAt && Date.now() - procAt < PROC_TTL) return procMap;
    try {
      const out = await run('tasklist', ['/fo', 'csv', '/nh']);
      for (const line of out.split(/\r?\n/)) {
        const m = line.match(/^"([^"]*)","(\d+)","([^"]*)","([^"]*)","([^"]*)"/);
        if (m) procMap.set(Number(m[2]), { name: m[1], mem: m[3], session: m[4] });
      }
      procAt = Date.now();
    } catch { /* 保持旧表 */ }
    return procMap;
  });
}

// ---------- 后台补全：可执行路径（判断是否系统进程、给风险分级） ----------
const exeMap = new Map(); // pid -> exe path
let exeAt = 0, exeRunning = false;
const CIM_ALL = 'Get-CimInstance Win32_Process | Select-Object ProcessId,ExecutablePath | ConvertTo-Json -Compress';
function enrichExe(force = false) {
  if (exeRunning || !force && exeAt && Date.now() - exeAt < CIM_TTL) return;
  exeRunning = true;
  run('powershell', ['-NoProfile', '-NonInteractive', '-Command', CIM_ALL], 30000)
    .then(out => {
      const j = JSON.parse(out.trim() || '[]');
      for (const p of Array.isArray(j) ? j : [j]) {
        if (p && p.ProcessId != null) exeMap.set(Number(p.ProcessId), p.ExecutablePath || '');
      }
      exeAt = Date.now();
    })
    .catch(() => { exeAt = Date.now() - CIM_TTL + 30000; }) // 失败 30s 后重试
    .finally(() => { exeRunning = false; });
}

// ---------- 风险分级 ----------
const HARD_BLOCK = new Set([
  'system', 'system idle process', 'registry', 'memory compression', 'secure system',
  'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'lsass.exe',
  'svchost.exe', 'fontdrvhost.exe', 'msmpeng.exe', 'securityhealthservice.exe', 'wudfhost.exe',
]);
function riskOf(pid, name, exe) {
  if (pid === process.pid) return 'self';
  if (pid === 0 || pid === 4) return 'blocked';
  const n = String(name || '').toLowerCase();
  if (HARD_BLOCK.has(n)) return 'blocked';
  if (!name && !exe) return 'caution';                 // 拿不到信息，谨慎
  if (/^c:\\windows\\/i.test(String(exe || '')) && n.endsWith('.exe') && n !== 'explorer.exe') return 'caution';
  if (n === 'explorer.exe' || n === 'dwm.exe') return 'caution';
  return 'normal';
}

// ---------- 变更追踪（新端口 / 关闭端口 / 首见时间） ----------
const seen = new Map();     // key -> { firstSeen, lastSeen, info }
const events = [];          // 环形事件流
let baselineDone = false;

function pushEvent(type, p) {
  const ev = {
    t: Date.now(), type, proto: p.proto, port: p.port, pid: p.pid,
    process: p.process, scope: p.scope, ephemeral: !!p.ephemeral,
  };
  events.push(ev);
  if (events.length > EVENT_MAX) events.splice(0, events.length - EVENT_MAX);
  fs.appendFile(EVENT_LOG, JSON.stringify(ev) + '\n', () => {});
}

function loadHistory() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const st = fs.statSync(EVENT_LOG);
    if (st.size > 2 * 1024 * 1024) {
      const tail = fs.readFileSync(EVENT_LOG, 'utf8').split('\n').slice(-500).join('\n');
      fs.writeFileSync(EVENT_LOG, tail);
    }
    const lines = fs.readFileSync(EVENT_LOG, 'utf8').trim().split('\n').slice(-300);
    for (const line of lines) {
      if (!line) continue;
      try { events.push(JSON.parse(line)); } catch { /* 跳过坏行 */ }
    }
  } catch { /* 首次运行无文件 */ }
}

function trackChanges(ports, now) {
  const live = new Set();
  for (const p of ports) {
    const key = `${p.proto}/${p.port}/${p.pid}`;
    live.add(key);
    let h = seen.get(key);
    if (!h) {
      // 首帧发现的端口属于「基线」，不算新增，也不会刷出 open 事件
      const baseline = !baselineDone;
      h = { firstSeen: baseline ? STARTED_AT : now, lastSeen: now, baseline, p };
      seen.set(key, h);
      if (!baseline) pushEvent('open', p);
    } else {
      h.lastSeen = now;
      h.p = p;
    }
  }
  if (baselineDone) {
    for (const [key, h] of seen) {
      // 给 4s 宽限期，避免刷新抖动产生假关闭事件
      if (!live.has(key) && now - h.lastSeen > 4000) {
        pushEvent('close', h.p);
        seen.delete(key);
      }
    }
  }
  for (const p of ports) {
    const h = seen.get(`${p.proto}/${p.port}/${p.pid}`);
    p.firstSeen = h ? h.firstSeen : now;
    p.isNew = !!h && !h.baseline;
  }
  baselineDone = true;
}

// ---------- 快照 ----------
let snap = { at: 0, data: null };

async function buildSnapshot() {
  const { sockets, costMs } = await scanSockets();
  const procs = await processTable();

  // 出现未知 PID（新进程刚起监听）时同步刷新一次进程表，否则首帧与事件里只能写「未知进程」
  const missing = [...new Set(sockets.map(s => s.pid))].filter(p => p && !procs.has(p));
  if (missing.length && Date.now() - lastForceProc > 2000) {
    lastForceProc = Date.now();
    await processTable(true).catch(() => {});
  }
  enrichExe();

  const groups = new Map();
  for (const s of sockets) {
    if (s.proto === 'TCP' && s.state !== 'LISTENING') continue;
    if (!Number.isFinite(s.localPort)) continue;
    const key = `${s.proto}/${s.localPort}`;
    let g = groups.get(key);
    if (!g) {
      g = { proto: s.proto, port: s.localPort, pids: new Set(), hosts: new Map(), scope: 'loopback' };
      groups.set(key, g);
    }
    g.pids.add(s.pid);
    g.hosts.set(s.localHost, (g.hosts.get(s.localHost) || 0) + 1);
    const c = classify(s.localHost);
    if (SCOPE_RANK[c] > SCOPE_RANK[g.scope]) g.scope = c;
  }

  // 连接明细：按监听端口索引（本地端口 = 监听端口，即入向连接）
  const connsByPort = new Map();
  const pushConn = (port, c) => {
    if (!connsByPort.has(port)) connsByPort.set(port, []);
    connsByPort.get(port).push(c);
  };
  let established = 0;
  for (const s of sockets) {
    if (s.proto !== 'TCP' || s.state === 'LISTENING') continue;
    if (s.state === 'ESTABLISHED') established++;
    if (!['ESTABLISHED', 'TIME_WAIT', 'CLOSE_WAIT', 'SYN_SENT', 'FIN_WAIT_2'].includes(s.state)) continue;
    pushConn(s.localPort, {
      remote: `${s.remoteHost}:${s.remotePort}`,
      state: s.state,
      pid: s.pid,
      proc: s.pid ? (procs.get(s.pid)?.name || '') : '',
    });
  }

  const ports = [];
  for (const g of groups.values()) {
    const pids = [...g.pids].filter(Boolean);
    const pid = pids[0] ?? 0;
    const proc = procs.get(pid) || {};
    const name = proc.name || (pid === 0 ? 'System Idle' : pid === 4 ? 'System' : '未知进程');
    const exe = exeMap.get(pid) || '';
    const list = connsByPort.get(g.port) || [];
    const states = {};
    for (const c of list) states[c.state] = (states[c.state] || 0) + 1;
    const clients = new Set(list.filter(c => c.pid && c.pid !== pid).map(c => c.pid));

    ports.push({
      proto: g.proto,
      port: g.port,
      service: SERVICE_NAMES[g.port] || null,
      addr: [...g.hosts.keys()].join(', '),
      addrs: [...g.hosts.keys()],
      scope: g.scope,
      pid,
      extraPids: pids.slice(1),
      process: name,
      mem: proc.mem || '',
      exe,
      risk: riskOf(pid, name, exe),
      connections: states.ESTABLISHED || 0,
      states,
      conns: list.slice(0, 30),
      clients: clients.size,   // 有多少个不同进程正在连这个端口
      ephemeral: g.port >= EPHEMERAL_MIN,
    });
  }

  ports.sort((a, b) => a.port - b.port || a.proto.localeCompare(b.proto));
  trackChanges(ports, Date.now());

  const data = {
    updatedAt: new Date().toISOString(),
    startedAt: STARTED_AT,
    version: VERSION,
    scanMs: costMs,
    summary: {
      listeners: ports.length,
      processes: new Set(ports.map(p => p.pid)).size,
      tcp: ports.filter(p => p.proto === 'TCP').length,
      udp: ports.filter(p => p.proto === 'UDP').length,
      established,
      exposed: ports.filter(p => p.scope === 'wildcard').length,
      fresh: ports.filter(p => p.isNew && !p.ephemeral).length,
      guarded: ports.filter(p => p.risk === 'blocked').length,
    },
    ports,
  };
  snap = { at: Date.now(), data };
  return data;
}

async function getSnapshot(force = false) {
  if (!force && snap.data && Date.now() - snap.at < SNAPSHOT_TTL) return snap.data;
  return single.do('snapshot', async () => {
    if (!force && snap.data && Date.now() - snap.at < SNAPSHOT_TTL) return snap.data;
    return await buildSnapshot();
  });
}

// ---------- 进程详情 ----------
const detailCache = new Map();
async function processDetail(pid) {
  const hit = detailCache.get(pid);
  if (hit && Date.now() - hit.at < 60000) return hit.data;
  const script = [
    `$p = Get-CimInstance Win32_Process -Filter "ProcessId=${pid}" | Select-Object -First 1`,
    'if (-not $p) { "{}"; exit }',
    '$pp = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.ParentProcessId)" | Select-Object -First 1',
    '[pscustomobject]@{ Name=$p.Name; CommandLine=$p.CommandLine; ExecutablePath=$p.ExecutablePath;',
    'ParentPid=$p.ParentProcessId; ParentName=$pp.Name; Created=$p.CreationDate;',
    'WorkingSet=$p.WorkingSetSize; Threads=$p.ThreadCount } | ConvertTo-Json -Compress',
  ].join('; ');
  let data = { name: '', commandLine: '', executablePath: '', parentPid: 0, parentName: '', created: '', workingSet: 0, threads: 0 };
  try {
    const out = await run('powershell', ['-NoProfile', '-NonInteractive', '-Command', script], 20000);
    const j = JSON.parse(out.trim() || '{}');
    let created = '';
    if (j.Created) {
      const m = String(j.Created).match(/\/Date\((\d+)/);
      created = m ? new Date(Number(m[1])).toISOString() : String(j.Created);
    }
    data = {
      name: j.Name || '',
      commandLine: j.CommandLine || '',
      executablePath: j.ExecutablePath || '',
      parentPid: j.ParentPid || 0,
      parentName: j.ParentName || '',
      created,
      workingSet: j.WorkingSet || 0,
      threads: j.Threads || 0,
    };
  } catch { /* 进程已退出或权限不足 */ }
  detailCache.set(pid, { at: Date.now(), data });
  return data;
}

// ---------- 端口探活（识别端口背后到底是什么服务） ----------
function tcpPing(port, timeout = 900) {
  return new Promise(resolve => {
    const t0 = process.hrtime.bigint();
    const s = net.connect({ host: '127.0.0.1', port, timeout });
    const done = ok => {
      s.destroy();
      resolve({ ok, ms: Number(process.hrtime.bigint() - t0) / 1e6 });
    };
    s.once('connect', () => done(true));
    s.once('timeout', () => done(false));
    s.once('error', () => done(false));
  });
}

function httpBanner(port, secure, timeout = 1200) {
  return new Promise(resolve => {
    let settled = false;
    const done = v => { if (!settled) { settled = true; resolve(v); } };
    // 兜底：即便响应流被提前 destroy，也保证请求不会挂住
    const guard = setTimeout(() => done({ ok: false, error: 'timeout' }), timeout + 400);
    const finish = v => { clearTimeout(guard); done(v); };
    const mod = secure ? https : http;
    const req = mod.request({
      host: '127.0.0.1', port, path: '/', method: 'GET',
      headers: { Host: `127.0.0.1:${port}`, 'User-Agent': 'Portboard-Probe/2.0', Accept: '*/*' },
      timeout, rejectUnauthorized: false,
    }, res => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', c => { body += c; if (body.length > 4096) { req.destroy(); } });
      res.on('end', () => {
        const title = (body.match(/<title[^>]*>([\s\S]{0,120}?)<\/title>/i) || [, ''])[1].trim();
        finish({
          ok: true, status: res.statusCode, server: res.headers.server || '',
          poweredBy: res.headers['x-powered-by'] || '', title,
          location: res.headers.location || '',
        });
      });
      res.on('error', () => finish({ ok: false }));
    });
    req.on('timeout', () => { req.destroy(); finish({ ok: false, error: 'timeout' }); });
    req.on('error', e => finish({ ok: false, error: e.code || 'error' }));
    req.end();
  });
}

async function probePort(port, proto) {
  if (proto === 'UDP') return { reachable: false, note: 'UDP 无法主动探测（无连接语义）' };
  const ping = await tcpPing(port);
  if (!ping.ok) return { reachable: false, connectMs: Math.round(ping.ms), note: 'TCP 连接被拒绝或超时' };
  const out = { reachable: true, connectMs: Math.round(ping.ms) };
  const sec = [443, 8443, 9443].includes(port);
  let banner = await httpBanner(port, sec);
  if (!banner.ok && !sec) banner = await httpBanner(port, true);
  if (banner.ok) {
    out.http = banner;
    out.protocol = banner.status ? (sec ? 'HTTPS' : 'HTTP') : 'TCP';
  } else {
    out.protocol = 'TCP';
    out.note = '非 HTTP 协议或无响应头';
  }
  return out;
}

// ---------- 终止进程 ----------
function alive(pid) {
  try { process.kill(pid, 0); return true; }
  catch (e) { return e.code === 'EPERM'; }
}

class HttpError extends Error {
  constructor(status, message, extra = {}) { super(message); this.status = status; this.extra = extra; }
}

let killLock = false;
async function killProcess(pid, opts = {}) {
  const { port, proto, force } = opts;
  if (killLock) throw new HttpError(429, '已有终止操作正在执行，请稍候');
  killLock = true;
  try {
    if (pid === process.pid) throw new HttpError(400, '不能终止 Portboard 自身');
    if (pid === 0 || pid === 4) throw new HttpError(403, 'PID 0/4 是内核线程，不可终止');

    const procs = await processTable();
    const name = procs.get(pid)?.name || '';
    const exe = exeMap.get(pid) || '';
    const risk = riskOf(pid, name, exe);
    if (risk === 'blocked' && !force) {
      throw new HttpError(403, `${name || 'PID ' + pid} 属于受保护的系统进程，默认拒绝终止`, { risk });
    }
    if (!alive(pid)) throw new HttpError(409, '进程已不存在，请刷新');

    // 端口归属校验：防止 PID 复用 / 页面数据过期导致杀错进程
    if (port) {
      const { sockets } = await scanSockets();
      const owner = sockets.find(s => s.localPort === Number(port) && s.proto === proto);
      if (!owner) throw new HttpError(409, `端口 ${port} 已不再监听，请刷新后重试`);
      if (owner.pid !== pid) throw new HttpError(409, `端口 ${port} 当前属于 PID ${owner.pid}，与你操作的对象不一致`, { actualPid: owner.pid });
    }

    // 该进程占用的全部端口 —— 终止前告知用户影响面（一个进程可能占多个端口）
    const snapData = await getSnapshot();
    const affected = snapData.ports.filter(p => p.pid === pid).map(p => ({ proto: p.proto, port: p.port }));

    let mode = 'forced';
    try {
      await execFileP('taskkill', ['/PID', String(pid)], { windowsHide: true, encoding: 'buffer' });
      mode = 'graceful';
    } catch { /* 无响应窗口的进程会失败，继续走强杀 */ }
    if (mode === 'graceful') {
      for (let i = 0; i < 8 && alive(pid); i++) await sleep(120);
    }
    if (alive(pid)) {
      try {
        await execFileP('taskkill', ['/PID', String(pid), '/F', '/T'], { windowsHide: true, encoding: 'buffer' });
        mode = 'forced';
      } catch (e) {
        const msg = decode(e.stderr || Buffer.from(String(e.message))).trim() || '终止失败';
        throw new HttpError(403, /拒绝|denied|Access/i.test(msg) ? '权限不足：请以管理员身份重启 Portboard' : msg);
      }
    }
    await sleep(250);
    procAt = 0;
    await getSnapshot(true).catch(() => {});
    return { ok: true, pid, name, mode, affected, risk };
  } finally {
    killLock = false;
  }
}

// ---------- 系统信息 ----------
let elevCache = { at: 0, value: false };
async function isElevated() {
  if (Date.now() - elevCache.at < 300000) return elevCache.value;
  let value = false;
  try { await execFileP('net', ['session'], { windowsHide: true, encoding: 'buffer' }); value = true; } catch { value = false; }
  elevCache = { at: Date.now(), value };
  return value;
}

// ---------- HTTP ----------
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
  '.png': 'image/png', '.json': 'application/json; charset=utf-8',
};
const SEC_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Cache-Control': 'no-store',
};

function json(res, obj, code = 200) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', ...SEC_HEADERS });
  res.end(JSON.stringify(obj));
}

function readBody(req, limit = 1e5) {
  return new Promise((resolve, reject) => {
    let s = '';
    req.on('data', c => { s += c; if (s.length > limit) { req.destroy(); reject(new HttpError(413, '请求体过大')); } });
    req.on('end', () => { try { resolve(s ? JSON.parse(s) : {}); } catch { reject(new HttpError(400, 'JSON 解析失败')); } });
    req.on('error', reject);
  });
}

// 本机校验：DNS rebinding + CSRF 防护
const HOST_RE = new RegExp(`^(127\\.0\\.0\\.1|localhost|\\[::1\\]):${PORT}$`, 'i');
const ORIGIN_RE = new RegExp(`^http://(127\\.0\\.0\\.1|localhost):${PORT}$`, 'i');
function checkLocal(req, res) {
  const ra = req.socket.remoteAddress || '';
  if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(ra)) {
    json(res, { ok: false, error: '仅允许本机访问' }, 403); return false;
  }
  const host = String(req.headers.host || '');
  if (!HOST_RE.test(host)) { json(res, { ok: false, error: 'Host 校验失败（可能是 DNS 重绑定攻击）' }, 403); return false; }
  const origin = req.headers.origin;
  if (origin && !ORIGIN_RE.test(origin)) { json(res, { ok: false, error: 'Origin 校验失败' }, 403); return false; }
  return true;
}

function indexHtml() {
  const file = path.join(PUBLIC_DIR, 'index.html');
  return fs.readFileSync(file, 'utf8').replaceAll('__PB_TOKEN__', TOKEN);
}

function toCsv(data) {
  const head = ['端口', '协议', '服务', '暴露范围', '进程', 'PID', '可执行路径', 'risk', '活跃连接', 'TIME_WAIT', '监听地址', '首见'];
  const rows = data.ports.map(p => [
    p.port, p.proto, p.service || '', p.scope, p.process, p.pid, p.exe, p.risk,
    p.connections, p.states.TIME_WAIT || 0, p.addrs.join(' | '), new Date(p.firstSeen).toLocaleString('zh-CN'),
  ]);
  const esc = v => {
    const s = String(v ?? '');
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  return '\ufeff' + [head, ...rows].map(r => r.map(esc).join(',')).join('\r\n');
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${HOST}:${PORT}`);
  const p = url.pathname;

  if (!checkLocal(req, res)) return;

  // 写操作必须带令牌：任意本地网页无法读取该令牌，因此无法伪造 POST
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.headers['x-portboard-token'] !== TOKEN) {
    return json(res, { ok: false, error: '缺少或错误的令牌' }, 403);
  }

  try {
    if (p === '/api/ports') return json(res, await getSnapshot());
    if (p === '/api/system') {
      return json(res, {
        hostname: os.hostname(), platform: `${os.type()} ${os.release()}`,
        arch: os.arch(), uptime: os.uptime(), cpus: os.cpus().length,
        totalMem: os.totalmem(), freeMem: os.freemem(),
        elevated: await isElevated(), version: VERSION, startedAt: STARTED_AT,
      });
    }
    if (p === '/api/events') {
      const n = clampNum(Number(url.searchParams.get('limit') || 80), 1, 400);
      return json(res, { ok: true, events: events.slice(-n).reverse() });
    }
    if (p === '/api/probe') {
      const port = Number(url.searchParams.get('port'));
      const proto = (url.searchParams.get('proto') || 'TCP').toUpperCase();
      if (!Number.isInteger(port) || port < 1 || port > 65535) return json(res, { ok: false, error: '端口无效' }, 400);
      return json(res, { ok: true, ...(await probePort(port, proto)) });
    }
    if (p === '/api/export') {
      const csv = toCsv(await getSnapshot());
      res.writeHead(200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="portboard-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '')}.csv"`,
        ...SEC_HEADERS,
      });
      return res.end(csv);
    }
    let m = p.match(/^\/api\/process\/(\d+)$/);
    if (m) return json(res, await processDetail(Number(m[1])));

    if (p === '/api/kill') {
      if (req.method !== 'POST') return json(res, { ok: false, error: '请用 POST' }, 405);
      const b = await readBody(req);
      const pid = Number(b.pid);
      const port = b.port == null ? null : Number(b.port);
      if (!Number.isInteger(pid) || pid <= 0) return json(res, { ok: false, error: '无效 PID' }, 400);
      const r = await killProcess(pid, { port, proto: String(b.proto || 'TCP').toUpperCase(), force: b.force === true });
      return json(res, r);
    }

    // 静态资源
    if (p === '/' || p === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...SEC_HEADERS });
      return res.end(indexHtml());
    }
    let file = path.normalize(p).replace(/^(\.\.[/\\])+/, '');
    const full = path.join(PUBLIC_DIR, file);
    if (!full.startsWith(PUBLIC_DIR) || !fs.existsSync(full) || fs.statSync(full).isDirectory()) {
      res.writeHead(404, SEC_HEADERS).end('Not Found');
      return;
    }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream', ...SEC_HEADERS });
    fs.createReadStream(full).pipe(res);
  } catch (err) {
    if (err instanceof HttpError) return json(res, { ok: false, error: err.message, ...err.extra }, err.status);
    json(res, { ok: false, error: String(err.message || err) }, 500);
  }
});

loadHistory();
processTable().catch(() => {});
server.listen(PORT, HOST, () => {
  console.log(`[Portboard ${VERSION}] http://${HOST}:${PORT}`);
  console.log(`[Portboard] 端口表 ${SNAPSHOT_TTL}ms TTL · 进程表 ${PROC_TTL / 1000}s TTL · 事件日志 ${EVENT_LOG}`);
});
server.on('error', e => {
  console.error(`[Portboard] 端口 ${PORT} 启动失败: ${e.message}`);
  process.exit(1);
});
