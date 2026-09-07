#!/usr/bin/env node
/**
 * panel_render_check.js — 面板渲染级验收 (v0.6.4, 决策 #51 落地)
 *
 * 背景 (决策 #51 / v0.6.2.1 白屏教训):
 *   `curl -o /dev/null -w %{http_code}` 只证明 HTML 与静态资源**可达**,
 *   无法发现**浏览器渲染失败** —— app.js 一处字面 \n 损坏就让 Vue 永不挂载,
 *   HTTP 层却全 200。故面板验收必须到**渲染级**:
 *     1. 语法门禁: node --check server/static/app.js
 *     2. 无头挂载: 真实 vendor JS + app.js 在 DOM 中执行, 断言 DOM 真的渲染出来
 *     3. v0.6.4 契约: 资产状态机常量在运行时可见 (证明新代码真的被解析执行)
 *
 * 用法:
 *   node scripts/panel_render_check.js          # 完整模式 (需 jsdom)
 *   PANEL_CHECK_NO_JSDOM=1 node scripts/...     # 强制降级模式
 *
 * jsdom 解析顺序 (免污染仓库依赖, jsdom 不进 requirements.txt):
 *   $PANEL_CHECK_NODE_PATH → /tmp/panelcheck/node_modules → 常规 node_modules
 *   都找不到 → **降级**: 仅跑语法门禁 + 静态断言, 退出码 0 但打印
 *   `⚠️ DEGRADED`, 并在摘要里如实标注「无头挂载未执行」(诚实标注纪律)。
 */

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const STATIC = path.join(ROOT, 'server', 'static');
const APP_JS = path.join(STATIC, 'app.js');
const INDEX_HTML = path.join(STATIC, 'index.html');

const results = [];
let degraded = false;

function record(name, ok, detail) {
  results.push({ name, ok, detail: detail || '' });
  console.log(`${ok ? '  ✅' : '  ❌'} ${name}${detail ? ' — ' + detail : ''}`);
}

// ------------------------------------------------------------------
// 1. 语法门禁 (node --check)
// ------------------------------------------------------------------
console.log('\n[1/3] 语法门禁 node --check');
let syntaxOk = true;
try {
  execFileSync(process.execPath, ['--check', APP_JS], { stdio: 'pipe' });
  record('app.js 语法', true, 'node --check 通过');
} catch (e) {
  syntaxOk = false;
  record('app.js 语法', false, String(e.stderr || e.message).split('\n')[0]);
}

// ------------------------------------------------------------------
// 2. 静态契约断言 (v0.6.4 前端资产确认闭环)
// ------------------------------------------------------------------
console.log('\n[2/3] v0.6.4 静态契约');
const src = fs.readFileSync(APP_JS, 'utf8');
const html = fs.readFileSync(INDEX_HTML, 'utf8');

const STATIC_CHECKS = [
  ['资产状态机常量 ASSET_STATES', /const ASSET_STATES = \{[^}]*PENDING_REVIEW/],
  ['分级标签 = 业务重要性 (核心/重要/一般/边缘)',
    /LEVEL_LABELS = \{ critical: '核心', high: '重要', medium: '一般', low: '边缘' \}/],
  ['待确认横幅 (个新资产待人工确认)', /个新资产待人工确认/],
  ['一键信任全部', /一键信任全部/],
  ['批量确认 batchTrust', /function batchTrust|batchTrust\s*\(/],
  ['确认弹窗 confirmDialog', /confirmDialog/],
  ['呼吸闪烁 startBlink', /function startBlink/],
  // 多选并列筛选: 分级/镜像/命名空间/节点均为数组 (OR 语义)
  // 注: 下拉已改绑 draftFilter (暂存), 应用后才写入 topoFilter
  ['分级多选 draftFilter.levels', /v-model="draftFilter\.levels"[^>]*multiple/],
  ['镜像多选 draftFilter.images', /v-model="draftFilter\.images"[^>]*multiple/],
  ['命名空间多选 draftFilter.nss', /v-model="draftFilter\.nss"[^>]*multiple/],
  ['节点多选 draftFilter.nodes', /v-model="draftFilter\.nodes"[^>]*multiple/],
  ['多选 OR 语义谓词 inSet', /const inSet = \(sel, val\)/],
  // 筛选改为「暂存 + 应用」: 下拉绑 draftFilter, 点按钮才提交
  ['筛选草稿 draftFilter', /draftFilter\.levels/],
  ['应用筛选按钮', /@click="applyFilter">应用筛选/],
  ['未应用提示 filterDirty', /filterDirty.*未应用|条件已改, 未应用/s],
  // 多选下拉不应再带 @change 即时重绘 (改为点按钮应用)
  ['下拉不再即时重绘', /v-model="draftFilter\.levels"(?![^>]*@change)/s],
  ['前端 openRevert', /function openRevert/],
  ['撤销原因必填', /撤销必须填写原因/],
  ['待确认虚线边框 (itemStyle + borderType dashed)',
    /itemStyle:\s*\w+\.asset_state === 'PENDING_REVIEW'[\s\S]{0,300}borderType:\s*'dashed'/],
  ['ElNotification 新资产提示', /ElNotification\(\{/],
  ['留痕入口 /audit', /\/audit'\s*\)|assets\/.*audit/],
];
for (const [name, re] of STATIC_CHECKS) {
  record(name, re.test(src));
}

// 后端契约检查 (v0.6.4 撤销能力): 前端静态断言只覆盖 app.js,
// revert 的实现与端点在 Python 侧, 必须单独断言否则会"前端有按钮后端没有接口"
const BACKEND_CHECKS = [
  ['后端 AssetStore.revert', path.join(ROOT, 'src', 'core', 'assets.py'),
    /def revert\(self, asset_id, by_user, reason\)/],
  ['revert 端点 + admin 权限', path.join(ROOT, 'server', 'routes.py'),
    /@router\.post\("\/assets\/\{asset_id\}\/revert"\)[\s\S]{0,200}admin_only/],
  ['confirm 端点 = write_op (admin+operator)',
    path.join(ROOT, 'server', 'routes.py'),
    /assets\/\{asset_id\}\/confirm"\)[\s\S]{0,120}write_op/],
];
for (const [name, file, re] of BACKEND_CHECKS) {
  if (!fs.existsSync(file)) { record(name, false, '文件不存在: ' + file); continue; }
  record(name, re.test(fs.readFileSync(file, 'utf8')));
}

// index.html 缓存参数: 确认浏览器会拉到新代码 (v=NN)
const vMatch = html.match(/app\.js\?v=(\d+)/);
record('index.html 缓存参数存在', !!vMatch, vMatch ? `app.js?v=${vMatch[1]}` : '未找到 ?v=');

// ------------------------------------------------------------------
// 3. 无头挂载 (jsdom: 真实 vendor JS + app.js 执行, 断言 DOM 渲染)
// ------------------------------------------------------------------
console.log('\n[3/3] 无头挂载渲染断言');

function resolveJsdom() {
  if (process.env.PANEL_CHECK_NO_JSDOM === '1') return null;
  const candidates = [];
  if (process.env.PANEL_CHECK_NODE_PATH) {
    candidates.push(path.join(process.env.PANEL_CHECK_NODE_PATH, 'jsdom'));
  }
  candidates.push('/tmp/panelcheck/node_modules/jsdom', 'jsdom');
  for (const c of candidates) {
    try {
      return require(c);
    } catch (e) { /* try next */ }
  }
  return null;
}

let jsdom = null;
try {
  jsdom = resolveJsdom();
} catch (e) {
  jsdom = null;
}

if (!jsdom) {
  degraded = true;
  console.log('  ⚠️  DEGRADED: 未找到 jsdom, 跳过无头挂载');
  console.log('     安装 (dev-only, 不入仓库依赖):');
  console.log('       npm install --prefix /tmp/panelcheck jsdom');
  console.log('       PANEL_CHECK_NODE_PATH=/tmp/panelcheck/node_modules node scripts/panel_render_check.js');
} else {
  // 用最小 DOM 起 jsdom, 再按 index.html 的顺序 eval 真实脚本文件。
  // 不走 jsdom 的资源加载器: jsdom 30 起 ResourceLoader 已移除 (改 requestInterceptor),
  // 直接 eval 文件跨版本稳定, 且完全等价于浏览器按序执行这些脚本。
  const { JSDOM, VirtualConsole } = jsdom;
  // ECharts 要 canvas 2d context, jsdom 无实现 → 必抛 "Not implemented:
  // HTMLCanvasElement's getContext()"。这是测试环境限制, 不是面板缺陷,
  // 用 VirtualConsole 精确过滤, 避免噪音淹没真实断言 (拓扑图渲染本检查不验)。
  const vc = new VirtualConsole();
  vc.on('jsdomError', (e) => {
    const m = String((e && e.message) || e || '');
    if (m.includes('getContext') || m.includes('clearRect')) return;
    console.error('  [jsdomError] ' + m.split('\n')[0]);
    if (process.env.PANEL_CHECK_TRACE) {
      console.error(String((e && e.stack) || '').split('\n').slice(0, 8).join('\n'));
    }
  });
  vc.on('error', (m, stack) => {
    const t = String(m);
    if (t.includes('getContext') || t.includes('clearRect')) return;
    console.error('  [page-error] ' + t.split('\n')[0]);
    if (process.env.PANEL_CHECK_TRACE) {
      console.error(String(stack || '').split('\n').slice(0, 6).join('\n'));
    }
  });
  const dom = new JSDOM(
    '<!DOCTYPE html><html><head></head><body><div id="app"></div></body></html>',
    {
      url: 'http://localhost:8000/',
      runScripts: 'dangerously',   // 允许 window.eval 执行脚本
      pretendToBeVisual: true,     // requestAnimationFrame (Vue / ECharts 需要)
      virtualConsole: vc,          // 过滤 canvas 噪音
    });
  const { window } = dom;

  const loadErr = [];
  window.addEventListener('error', (e) => {
    loadErr.push(String(e.message || e.error));
    if (process.env.PANEL_CHECK_TRACE) {
      console.error('  [TRACE] window.error: ' + String(e.message)
        + '\n' + String((e.error && e.error.stack) || '').split('\n').slice(1, 7).join('\n'));
    }
  });


  // jsdom 未实现的浏览器 API (浏览器原生有, 仅测试环境补) — 缺一即脚本中断,
  // 表现为「白屏」, 与决策 #51 的真实故障同形, 故必须在挂载前补齐。
  window.matchMedia = window.matchMedia || ((q) => ({
  matches: false, media: q, onchange: null,
  addListener() {}, removeListener() {},
  addEventListener() {}, removeEventListener() {}, dispatchEvent: () => false,
  }));
  window.ResizeObserver = window.ResizeObserver || class {
  observe() {} unobserve() {} disconnect() {}
  };
  // 组件 onMounted 会打 API。stub 返回**贴近真实的假数据**, 这样除了
  // 「模板能编译」还能断言「docker 容器真的被渲染出来」—— v0.6.4 的三处
  // 缺陷 (容器不可筛 / 不可再覆盖 / 无详情) 全是行为问题, 只编译不渲染查不出。
  const FAKE_ASSETS = {
    runtime: 'docker', total: 2, nodes: [], services: [], error: '',
    containers: [
      { id: 'aaaaaaaaaaaa', name: 'g-redis', image: 'redis:alpine', status: 'running',
        privileged: false, level: 'critical', level_source: 'auto',
        created: new Date(Date.now() - 3 * 3600 * 1000).toISOString().slice(0, 19),
        ip: '172.18.0.5', labels: { 'com.docker.compose.service': 'cache' },
        asset_state: 'PENDING_REVIEW', asset_rule: '数据库 / 密钥存储', audit_count: 1 },
      { id: 'bbbbbbbbbbbb', name: 'g-app', image: 'containous/whoami:latest',
        status: 'running', privileged: false, level: 'medium', level_source: 'override',
        created: new Date(Date.now() - 50 * 3600 * 1000).toISOString().slice(0, 19),
        asset_state: 'OVERRIDDEN', asset_rule: null, audit_count: 4 },
      // high(重要): 用于验证「核心 + 重要」多选并列真的取并集 (排除 medium 的 g-app)
      { id: 'cccccccccccc', name: 'g-nginx', image: 'nginx:alpine', status: 'running',
        privileged: false, level: 'high', level_source: 'auto',
        created: new Date(Date.now() - 10 * 3600 * 1000).toISOString().slice(0, 19),
        asset_state: 'PENDING_REVIEW', asset_rule: '网络组件', audit_count: 1 },
    ],
  };
  // 其余接口: 空壳但字段齐全。若一律返回 {}, 各页 onMounted 读
  // `x.recent_events.length` 等会抛 "reading 'length'", 那是**存根不完整**
  // 的产物而非面板缺陷 — 会淹没真实报错, 故补齐常见列表字段。
  // k8s 侧假数据: 与 docker 是同一类资产 (可确认/可覆盖), 差异只在来源。
  // 本机无 k8s 集群, 无法真机验收 → 至少用假数据保证归一化逻辑对 pod 成立,
  // 并在摘要里如实标注「k8s 侧未真机实测」。
  const FAKE_K8S = {
    runtime: 'k8s', total: 2, containers: [], services: [], error: '',
    nodes: [{
      name: 'node-1', pods: [
        { name: 'web-7d9f', namespace: 'default', node: 'node-1', status: 'Running',
          pod_ip: '10.42.0.7', images: ['nginx:1.25'], services: ['web-svc'],
          labels: { app: 'web', tier: 'frontend' }, privileged: false,
          created: new Date(Date.now() - 26 * 3600e3).toISOString().slice(0, 19),
          asset_id: 'k8s:default:web-7d9f', level: 'high', level_source: 'auto',
          asset_state: 'PENDING_REVIEW', asset_rule: '网络组件', audit_count: 1 },
        { name: 'db-0', namespace: 'data', node: 'node-1', status: 'Running',
          pod_ip: '10.42.0.9', images: ['mysql:8', 'exporter:latest'],
          services: [], labels: { app: 'db' }, privileged: true,
          created: new Date().toISOString().slice(0, 19),
          asset_id: 'k8s:data:db-0', level: 'critical', level_source: 'override',
          asset_state: 'OVERRIDDEN', asset_rule: '数据库', audit_count: 4 },
      ],
    }],
  };
  const EMPTY = {
    total: 0, total_alerts: 0, pending_review: 0, frozen: 0, netblocked: 0,
    ai_false_positives: 0, events: [], alerts: [], recent_events: [], rules: [],
    audit: [], items: [], rows: [], steps: [], profiles: [], members: [],
    tokens: [], services: [], containers: [], nodes: [], groups: [],
  };
  window.fetch = (url) => {
    const u = String(url);
    let body = EMPTY;
    // window.__useK8s 为真时返回 k8s 数据 (供 k8s 侧归一化断言使用)
    if (u.includes('/api/assets')) body = window.__useK8s ? FAKE_K8S : FAKE_ASSETS;
    else if (u.includes('/api/auth/me')) {
      body = { username: 'admin', role: 'admin', must_change_password: false };
    }
    return Promise.resolve({
      ok: true, status: 200,
      json: () => Promise.resolve(body),
      text: () => Promise.resolve(JSON.stringify(body)),
    });
  };
  // 组件读 localStorage 判断角色 (canWrite/isAdmin), 给 admin 以便断言覆盖入口
  window.localStorage.setItem('guard_me', JSON.stringify(
    { username: 'admin', role: 'admin' }));

  // 注: ECharts 桩在 vendor 脚本 eval 之后注入 (见下方 ECHARTS_STUB 段),
  // 此处只声明接收容器 — 顺序不能反, 否则 window.echarts 尚不存在。

  // index.html 中的脚本顺序 (vendor 优先, 与浏览器一致)
  const scripts = ['/vendor/vue.global.prod.js', '/vendor/element-plus.umd.min.js',
                   '/vendor/echarts.min.js', '/app.js'];
  // ECharts 需要 canvas 2d context, jsdom 无实现 → 真 init() 之后一切绘制都抛错,
  // buildTopo() 的筛选/节点构建逻辑就测不到了。用桩替换 init: 本检查关心的是
  // **数据流 (哪些节点入图)** 而不是像素, 桩把 setOption 的 series.data 接出来,
  // 于是「docker 容器是否入图 / 待确认标记是否正确」都能变成硬断言。
  // 必须在 echarts.min.js eval 之后、app.js eval 之前注入。
  let execErr = '';
  for (const s of scripts) {
    const file = path.join(STATIC, s);
    if (!fs.existsSync(file)) { execErr = `缺少 ${s}`; break; }
    let code = fs.readFileSync(file, 'utf8');
    // app.js 尾部追加探针: 顶层 const 属脚本词法作用域, 外部 eval 读不到,
    // 故在同一次执行里把 v0.6.4 常量挂到 window 供断言读取。
    if (s === '/app.js') {
      code += '\n;window.__probe = { states: ASSET_STATES, levels: LEVEL_LABELS,'
            + ' panels: { pages }, age: assetAge };';
    }
    try {
      window.eval(code);
      // echarts 已 eval 完成 → 此时才能替换 init (否则 window.echarts 不存在)
      if (s === '/vendor/echarts.min.js') {
        window.__topoData = null;
        // 累计记录每次 setOption: 页面组件带 5s 轮询, 多个实例共存时后写的会
        // 覆盖先写的, 只看"最后一次"会误判。故存日志, 断言时按内容查找。
        window.__topoLog = [];
        window.echarts.init = () => ({
          setOption: (o) => {
            const ser = o && o.series
              && (Array.isArray(o.series) ? o.series[0] : o.series);
            if (ser && ser.data) {
              window.__topoData = ser.data;
              window.__topoLog.push(ser.data);
            }
          },
          on: () => {}, off: () => {}, resize: () => {}, dispose: () => {},
        });
      }
    } catch (e) {
      execErr = `${s}: ${String(e.message).split('\n')[0]}`;
      break;
    }
  }

  new Promise((r) => setTimeout(r, 400)) // 让 Vue 完成首次 patch
    .then(() => {
      const app = window.document.querySelector('#app');
      const htmlOut = app ? app.innerHTML : '';

      record('脚本按序执行无异常', !execErr, execErr || 'vendor ×3 + app.js');
      record('未捕获脚本错误', loadErr.length === 0, loadErr[0] || '无');
      record('#app 已挂载 (非空白)', !!app && htmlOut.trim().length > 200,
        `${htmlOut.trim().length} 字节 innerHTML`);
      record('登录卡片渲染', /login-card/.test(htmlOut), 'login-card');

      // 运行时契约: v0.6.4 常量在真实执行后可见 → 证明新代码真的被解析执行
      // (仅静态 grep 无法区分「代码在」与「代码跑起来了」—— 白屏正是后者失败)
      const probe = window.__probe;
      const runtimeOk = !!probe && probe.states.PENDING_REVIEW === '待确认'
        && probe.levels.critical === '核心' && !!probe.panels.pages.assets;
      const runtimeDetail = probe
        ? `PENDING_REVIEW=${probe.states.PENDING_REVIEW}, `
          + `critical=${probe.levels.critical}, `
          + `pages=${Object.keys(probe.panels.pages).length} 个`
        : '探针未赋值 (app.js 未执行到底)';
      record('v0.6.4 常量 + 页面注册运行时可见', runtimeOk, runtimeDetail);

      // ---- 关键: 逐页模板编译 (v0.6.4 白屏根因正是模板损坏) ----
      // 只挂登录页不足以发现问题: 损坏发生在资产管理页模板里, 而它登录后
      // 才被编译。故对 pages 注册表里的**每一个**组件都真实 createApp().mount(),
      // 强制 Vue 编译其 template —— 模板语法/标签损坏在此必然抛错。
      const panels = probe && probe.panels;
      let assetsHost = null;
      if (panels && panels.pages) {
        for (const [key, page] of Object.entries(panels.pages)) {
          const host = window.document.createElement('div');
          window.document.body.appendChild(host);
          let err = '';
          try {
            window.Vue.createApp(page.comp)
              .use(window.ElementPlus)
              .mount(host);
          } catch (e) {
            err = String(e.message || e).split('\n')[0];
          }
          const rendered = (host.innerHTML || '').trim().length;
          record(`页面模板编译 [${key}] ${page.title}`, !err && rendered > 0,
            err ? err : `${rendered} 字节`);
          if (key === 'assets') assetsHost = host;
        }
      }

      // ---- 行为级断言: v0.6.4 三处缺陷的回归网 ----
      // 模板编译通过 ≠ 行为正确。下面断言「docker 容器在资产管理页里真的可见 /
      // 可筛 / 有详情与覆盖入口」—— 即用户肉眼看到的那三件事。
      // 注意: 数据在 onMounted 里异步 fetch, 必须等一拍再断言, 否则拿到空 DOM。
      //       Element Plus 的 placeholder 渲染为 <span>文本</span>, 不是属性。
      new Promise((r) => setTimeout(r, 900))
        .then(() => {
          if (!assetsHost) return;
          const h = assetsHost.innerHTML;
          // v0.6.4: 两张表 (k8s pod / docker 容器) 已合并为「统一资产清单」
          record('统一资产清单区块渲染', /资产清单/.test(h));
          record('类型列区分数据来源 (Pod / 容器)', /类型/.test(h));
          record('容器行渲染 (redis / whoami)',
            /g-redis/.test(h) && /containous\/whoami/.test(h));
          // 问题1: docker 容器可筛 — 分级/镜像维度 + docker 伪命名空间
          const hasPlaceholder = (t) =>
            new RegExp('<span>' + t + '</span>').test(h)
            || new RegExp('placeholder="' + t + '"').test(h);
          record('docker 可用筛选维度 (资产分级/镜像)',
            hasPlaceholder('资产分级') && hasPlaceholder('镜像'));
          // 资产状态不该再作为筛选维度: 待确认有顶栏+详情直达, 已覆盖属已决策
          record('已移除资产状态筛选', !hasPlaceholder('资产状态'));
          // docker 归入伪命名空间, 而非单独的显隐开关
          record('已移除「显示本地容器」开关', !/显示本地容器/.test(h));
          record('命名空间含 docker 伪命名空间',
            new RegExp('>' + 'docker' + '<').test(h) || /docker/.test(h));
          // 问题2: 已决策资产仍可覆盖 (OVERRIDDEN 行出现「覆盖」按钮)
          record('已决策资产有覆盖入口', /修改覆盖级别/.test(h) || />\s*覆盖\s*</.test(h));
          // 问题3: 详情入口 (列表行「详情」按钮)
          record('列表行有详情入口', /资产详情|>\s*详情\s*</.test(h));
          // 拓扑数据流断言 (ECharts 桩接出的 series.data):
          //   证明 docker 容器真的进图 + 待确认标记正确 — 这是「虚线闪烁」的前提
          const td = window.__topoData || [];
          const names = td.map(n => n && n.name);
          record('docker 容器入图 (拓扑节点)',
            names.includes('g-redis') && names.includes('g-app'),
            `节点: ${names.join(', ') || '无'}`);
          // 假数据中 g-redis(critical) 与 g-nginx(high) 均为 PENDING_REVIEW,
          // g-app(medium) 为 OVERRIDDEN → 待确认标记应恰好命中前两者
          const pend = td.filter(n => n && n.__pending).map(n => n.name);
          record('待确认标记仅 PENDING_REVIEW',
            pend.length === 2 && !pend.includes('g-app'),
            `__pending: ${pend.join(', ') || '无'}`);
          // 清单跟随筛选: 两个容器都应出现在容器清单表格里 (默认无筛选)
          record('容器清单跟随筛选 (默认全展示)',
            /g-redis/.test(h) && /containous\/whoami/.test(h));
          // v0.6.4: 创建时间 + 存活时长 (在详情弹窗里, 需开弹窗才渲染,
          // 故此处直接调组件暴露的 assetAge 验算, 确保换算逻辑不回归)
          // ---- 多选并列筛选: 真的点选「核心 + 重要」, 验证取并集 ----
          // 静态断言只能证明"写了 multiple", 证明不了 OR 语义生效。
          // 故模拟点击两个选项, 再看拓扑与清单是否只剩这两个分级的资产。
          const sel = [...assetsHost.querySelectorAll('.el-select')]
            .find(s => {
              const p = s.querySelector('.el-select__placeholder span');
              return p && p.textContent === '资产分级';
            });
          if (sel) {
            sel.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
          }
          return new Promise((r) => setTimeout(r, 400)).then(() => {
            if (!sel) { record('找到资产分级下拉', false); return; }
            record('找到资产分级下拉', true);
            const opts = [...window.document.querySelectorAll('.el-select-dropdown__item')]
              .filter(o => ['核心', '重要', '一般', '边缘'].includes(o.textContent.trim()));
            record('分级选项为新文案 (核心/重要/一般/边缘)', opts.length === 4,
              opts.map(o => o.textContent.trim()).join('/'));
            // 多选时 Element Plus 每次选中都会重渲染 dropdown, 之前缓存的
            // 选项 DOM 引用会失效 → 每次点击前必须重新查询, 且逐个串行点击
            const pick = (label) => {
              const o = [...window.document.querySelectorAll('.el-select-dropdown__item')]
                .find(x => x.textContent.trim() === label);
              if (o) o.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
              return !!o;
            };
            return new Promise((r2) => setTimeout(r2, 250))
              .then(() => pick('核心'))
              .then(() => new Promise((r3) => setTimeout(r3, 250)))
              .then(() => pick('重要'))
              .then(() => new Promise((r4) => setTimeout(r4, 250)))
              .then(() => {
                // 改为点「应用筛选」才生效: 直接调组件方法触发 applyFilter
                const btn = [...assetsHost.querySelectorAll('button')]
                  .find(b => /应用筛选/.test(b.textContent));
                if (btn) btn.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
                record('存在应用筛选按钮', !!btn);
              })
              .then(() => new Promise((r5) => setTimeout(r5, 700)));
          }).then(() => {
            const hSel = assetsHost.innerHTML;
            // 取最后一帧: 轮询每 5s 覆盖一次, 点选后 600ms 已重绘, 最后一帧即结果
            const log = window.__topoLog || [];
            const frame = log[log.length - 1] || [];
            const names = frame.map(n => n.name);
            record('多选并列: 核心+重要 同时入图',
              names.includes('g-redis') && names.includes('g-nginx')
              && !names.includes('g-app'),
              `节点: ${names.join(', ') || '无'}`);
            record('多选并列: 清单同步 (排除 一般 的 g-app)',
              /g-redis/.test(hSel) && /g-nginx/.test(hSel) && !/whoami/.test(hSel));
          });
        })
        .then(() => {
          // v0.6.4: 详情弹窗字段完整性 — 用户反馈「容器详情没有创建时间」。
          // 必须真的点开弹窗再断言, 静态 grep 只能证明"模板里写了",
          // 证明不了"渲染出来了" (assetAge 未导出就会整项静默消失)。
          const rowEl = assetsHost.querySelector('.el-table__body .el-table__row');
          if (rowEl) {
            rowEl.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
          }
          return new Promise((r) => setTimeout(r, 500)).then(() => {
            const dlg = [...window.document.querySelectorAll('.el-dialog')]
              .find(d => /资产详情/.test(d.textContent));
            if (!dlg) {
              record('详情弹窗可打开', false, '未找到资产详情弹窗');
              return;
            }
            const dt = dlg.textContent;
            // 字段名在 Element Plus 里可能是 label 单元格文本; 取不到就退回
            // 直接检查关键字段文案, 避免选择器差异导致误报
            const labels = [...dlg.querySelectorAll('.el-descriptions-item__label,'
              + '.el-descriptions__label')].map(x => x.textContent.trim());
            record('详情弹窗可打开', true,
              labels.length ? `字段: ${labels.join(' / ')}` : '字段已渲染 (类名未匹配)');
            record('详情弹窗含创建时间', /创建/.test(dt) && /\d{4}-\d{2}-\d{2}/.test(dt),
              /创建/.test(dt) ? '有创建项' : '缺少创建项');
            record('详情弹窗含存活时长', /已运行/.test(dt));
            // docker 侧同样有 IP 与 labels (compose 元数据), 不该一律留空
            record('详情弹窗含 IP 地址', /172\.18\.0\.5/.test(dt));
            record('详情弹窗含 Labels', /com\.docker\.compose\.service/.test(dt));
          });
        })
        .then(() => {
          // ---- k8s 侧归一化验证 ----
          // 本机无 k8s 集群, 无法真机验收。但统一清单的归一化逻辑对 pod 是否
          // 成立, 可以用假数据验证: 换数据源重挂一次, 断言 pod 出现在同一张表里。
          const host2 = window.document.createElement('div');
          window.document.body.appendChild(host2);
          window.__useK8s = true;      // 让 fetch stub 改返回 k8s 数据
          window.__topoData = null;
          try {
            window.Vue.createApp(probe.panels.pages.assets.comp)
              .use(window.ElementPlus).mount(host2);
          } catch (e) { /* 下方断言会报失败 */ }
          return new Promise((r) => setTimeout(r, 900)).then(() => {
            const h2 = host2.innerHTML;
            record('k8s pod 进入统一清单 (web-7d9f / db-0)',
              /web-7d9f/.test(h2) && /db-0/.test(h2));
            record('k8s 专属列有值 (Pod IP / 服务 / Labels)',
              /10\.42\.0\.7/.test(h2) && /web-svc/.test(h2) && /app=web/.test(h2));
            record('k8s 命名空间/节点列', /default \/ node-1/.test(h2));
            // 从累计日志里找含 pod 节点的那一帧 (docker 实例轮询会交替写入)
            // 注意: 拓扑节点名为可读性做了截断 (p.name.split('-')[0]),
            // 故 'web-7d9f' 在图上显示为 'web' — 断言须按实际规则匹配
            const frame = (window.__topoLog || [])
              .find(d => d.some(n => n && n.name === 'web')
                       && d.some(n => n && n.name === 'db'));
            record('k8s pod 入图 (拓扑)', !!frame,
              frame ? `节点: ${frame.map(n => n.name).join(', ')}`
                    : '未找到含 pod 的帧 (实际: '
                      + (window.__topoLog || []).map(d => d.map(n => n && n.name).join('/')).join(' | ') + ')');
            window.__useK8s = false;
          });
        })
        .then(() => { window.close(); summarize(); });
    })
    .catch((e) => {
      record('无头挂载执行', false, String(e.message).split('\n')[0]);
      summarize();
    });
}

function summarize() {
  const failed = results.filter((r) => !r.ok);
  console.log('\n' + '='.repeat(60));
  console.log(`通过 ${results.length - failed.length}/${results.length}`
    + (degraded ? '  ⚠️ DEGRADED (无头挂载未执行)' : ''));
  if (failed.length) {
    console.log('\n失败项:');
    for (const f of failed) console.log(`  - ${f.name}${f.detail ? ': ' + f.detail : ''}`);
  }
  console.log('='.repeat(60) + '\n');
  // 降级不算失败 (不阻断), 但语法错误 / 断言失败必须阻断
  process.exit(failed.length ? 1 : 0);
}

// 无 jsdom 时同步汇总
if (!jsdom) {
  summarize();
}
