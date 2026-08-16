/* eBPF Container Guard — 安全面板 SPA (v0.5.6)
 * Vue3 + Element Plus CDN, 零构建, 哈希路由。
 * 页面: overview / alerts / review_queue / behavior_log / rules / ai_rules / settings / members
 */
const { createApp, ref, reactive, computed, onMounted, onUnmounted } = Vue;
const ElMessage = ElementPlus.ElMessage;
const ElMessageBox = ElementPlus.ElMessageBox;

/* ================================================================
 * API 封装
 * ================================================================ */
async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    ...opts,
  });
  if (res.status === 401) {
    location.hash = '#/login';
    throw new Error('未登录');
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `请求失败 (${res.status})`);
  return data;
}
const get = (p) => api(p);
const post = (p, body) => api(p, { method: 'POST', body: JSON.stringify(body) });
const put = (p, body) => api(p, { method: 'PUT', body: JSON.stringify(body) });

/* ================================================================
 * 工具
 * ================================================================ */
const fmtTime = (t) => t ? String(t).replace('T', ' ').slice(0, 19) : '—';
// Unix 秒时间戳 → 本地时间 (toISOString 是 UTC, 会差 8 小时)
const fmtTs = (ts) => {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} `
       + `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
};
const sevClass = (s) => `sev-${(s || 'low').toLowerCase()}`;
const sevTag = (s) => {
  const m = { CRITICAL: 'danger', HIGH: 'warning', MEDIUM: 'primary', LOW: 'info' };
  return m[(s || '').toUpperCase()] || 'info';
};
// 角色 → 中文标签 + 颜色 (admin 黄 / operator 紫 / analyst 蓝)
const ROLE_LABELS = { admin: '管理员', operator: '运维', analyst: '安全员' };
const ROLE_COLORS = { admin: '', operator: '#722ed1', analyst: '' };
const ROLE_TYPES = { admin: 'warning', operator: 'danger', analyst: 'primary' };
// 角色等级 (与后端 ROLE_RANK 一致, 用于授权对象过滤)
const ROLE_RANK = { admin: 3, operator: 2, analyst: 1 };

function usePolling(fn, ms) {
  onMounted(() => { fn(); state.timer = setInterval(fn, ms); });
  onUnmounted(() => clearInterval(state.timer));
}
const state = { timer: null };

/* ================================================================
 * 登录页
 * ================================================================ */
const LoginPage = {
  props: ['onLoggedIn'],
  template: `
  <div class="login-wrap">
    <div class="login-card">
      <h1>🛡️ eBPF Container Guard</h1>
      <p class="sub">容器逃逸检测与防护 · 安全运维面板</p>
      <el-form :model="f" @submit.prevent="doLogin" label-position="top">
        <el-form-item label="用户名"><el-input v-model="f.username" placeholder="admin" /></el-form-item>
        <el-form-item label="密码"><el-input v-model="f.password" type="password" show-password
          placeholder="••••••••" @keyup.enter="doLogin" /></el-form-item>
        <el-button type="primary" style="width:100%" :loading="loading" @click="doLogin">登 录</el-button>
      </el-form>
      <p v-if="hint" style="margin-top:12px;font-size:12px;color:var(--warn)">{{ hint }}</p>
    </div>
  </div>`,
  setup(props) {
    const f = reactive({ username: 'admin', password: '' });
    const loading = ref(false);
    const hint = ref('');
    async function doLogin() {
      loading.value = true;
      try {
        await post('/api/auth/login', f);
        props.onLoggedIn && props.onLoggedIn();
        // 强制改密由 App 按 must_change_password 拦截
        location.hash = '#/overview';
      } catch (e) { ElMessage.error(e.message); }
      loading.value = false;
    }
    return { f, loading, hint, doLogin };
  },
};

/* ================================================================
 * Overview
 * ================================================================ */
const OverviewPage = {
  template: `
  <div>
    <div class="page-title">总览 <span class="sub">实时检测统计</span></div>
    <div class="kpi-row">
      <div class="kpi-card clickable" @click="goAlerts('all')"><div class="label">总告警</div><div class="value accent">{{ s.total_alerts }}</div></div>
      <div class="kpi-card clickable" @click="goPage('review')"><div class="label">待人工判决</div><div class="value warn">{{ s.pending_review }}</div></div>
      <div class="kpi-card clickable" @click="goAlerts('netblocked')"><div class="label">网络阻断</div><div class="value warn">{{ s.netblocked }}</div></div>
      <div class="kpi-card clickable" @click="goAlerts('aifp')"><div class="label">AI 误报</div><div class="value ok">{{ s.ai_false_positives }}</div></div>
      <div class="kpi-card clickable" @click="goAlerts('all')"><div class="label">已冻结容器</div><div class="value danger">{{ s.frozen }}</div></div>
    </div>
    <div class="panel">
      <h3>AI 研判配置
        <el-tag v-if="s.ai_config && s.ai_config.api_key_masked" size="small" type="success" style="margin-left:10px">
          {{ s.ai_config.model }} · {{ s.ai_config.api_key_masked }}
        </el-tag>
        <el-tag v-else size="small" type="info" style="margin-left:10px">未配置</el-tag>
      </h3>
    </div>
    <div class="panel">
      <h3>最近事件</h3>
      <el-table :data="s.recent_events" size="small" stripe @row-click="openEventDetail">
        <el-table-column label="时间" width="170"><template #default="{row}">{{ fmtTime(row.timestamp) }}</template></el-table-column>
        <el-table-column label="容器" width="200"><template #default="{row}"><span class="mono">{{ row.container_id }}</span></template></el-table-column>
        <el-table-column label="规则" min-width="180"><template #default="{row}">
          <span class="ev-rule">{{ row.rule }}</span></template></el-table-column>
        <el-table-column label="严重度" width="100"><template #default="{row}">
          <el-tag :type="sevTag(row.severity)" size="small">{{ row.severity }}</el-tag></template></el-table-column>
        <el-table-column label="动作" width="140"><template #default="{row}">
          <span v-if="row.action_status === 'executed'" class="mono" style="color:var(--ok)">{{ row.action }}</span>
          <span v-else class="mono" style="color:var(--muted)">{{ row.action }} ({{ row.action_status }})</span>
        </template></el-table-column>
      </el-table>
    </div>
  </div>`,
  setup() {
    const s = reactive({ total_alerts: 0, pending_review: 0, frozen: 0, netblocked: 0,
      ai_false_positives: 0, ai_config: null, recent_events: [] });
    async function load() {
      try { Object.assign(s, await get('/api/overview/stats')); } catch (e) {}
    }
    function goAlerts(f) {
      // OverviewPage 作用域无 route — 只改 hash, App 的 onHash 负责切页
      location.hash = '#/alerts?filter=' + f;
    }
    function goPage(key) { location.hash = '#' + key; }    usePolling(load, 3000);
    return { s, fmtTime, sevTag, goAlerts, goPage, openEventDetail };
  },
};

/* ================================================================
 * Alerts
 * ================================================================ */
const AlertsPage = {
  template: `
  <div>
    <div class="page-title">告警流 <span class="sub">最近 {{ events.length }} 条
      <el-tag v-if="curFilter !== 'all'" size="small" closable @close="clearFilter"
              style="margin-left:8px">{{ filterLabel }}</el-tag>
    </span></div>
    <div class="panel" style="display:flex;gap:12px;align-items:center;padding:12px 18px;flex-wrap:wrap">
      <el-input v-model="q.container" placeholder="容器搜索 (模糊)" style="width:220px"
                clearable size="small" @input="load" />
      <el-select v-model="q.rule" placeholder="规则" clearable size="small" style="width:200px"
                 @change="load">
        <el-option v-for="r in ruleOptions" :key="r" :label="r" :value="r" />
      </el-select>
      <el-select v-model="q.severity" placeholder="严重度" clearable size="small" style="width:120px"
                 @change="load">
        <el-option v-for="s in ['CRITICAL','HIGH','MEDIUM','LOW']" :key="s" :label="s" :value="s" />
      </el-select>
      <el-button v-if="q.container || q.rule || q.severity" size="small" @click="resetFilter">清除筛选</el-button>
    </div>
    <div class="panel">
      <el-table :data="events" size="small" stripe max-height="70vh"
                @row-click="openEventDetail">
        <el-table-column label="时间" width="170"><template #default="{row}">{{ fmtTime(row.timestamp) }}</template></el-table-column>
        <el-table-column label="容器" width="200"><template #default="{row}"><span class="mono">{{ row.container_id }}</span></template></el-table-column>
        <el-table-column label="规则" min-width="180"><template #default="{row}">
          <span class="ev-rule">{{ row.rule }}</span></template></el-table-column>
        <el-table-column label="严重度" width="100"><template #default="{row}">
          <el-tag :type="sevTag(row.severity)" size="small">{{ row.severity }}</el-tag></template></el-table-column>
        <el-table-column label="进程" width="150"><template #default="{row}">
          <span class="mono">{{ row.event?.comm || '—' }} ({{ row.event?.pid || '?' }})</span></template></el-table-column>
        <el-table-column label="动作" width="150"><template #default="{row}">
          <span class="mono" :style="{color: row.action_status === 'executed' ? 'var(--ok)' : 'var(--muted)'}">
            {{ row.action }} {{ row.action_status === 'executed' ? '' : '/' + row.action_status }}</span></template></el-table-column>
        <el-table-column label="人工判决" width="110"><template #default="{row}">
          <el-tag v-if="row.human_decision" :type="row.human_decision === 'confirmed' ? 'danger' : 'success'" size="small">
            {{ row.human_decision }}</el-tag>
          <span v-else style="color:var(--muted)">—</span></template></el-table-column>
      </el-table>
    </div>
  </div>`,
  setup() {
    const events = ref([]);
    const curFilter = ref('all');
    const filterLabel = computed(() =>
      ({ netblocked: '仅网络阻断', aifp: '仅 AI 误报' }[curFilter.value] || ''));
    const q = reactive({ container: '', rule: '', severity: '' });
    const ruleOptions = ref([]);
    async function load() {
      try {
        const p = new URLSearchParams();
        if (curFilter.value !== 'all') p.set('filter', curFilter.value);
        if (q.container) p.set('container', q.container);
        if (q.rule) p.set('rule', q.rule);
        if (q.severity) p.set('severity', q.severity);
        events.value = (await get('/api/alerts?' + p)).events;
        // 规则下拉选项 (从全量事件收集去重)
        if (ruleOptions.value.length === 0) {
          const all = (await get('/api/alerts?limit=200')).events;
          ruleOptions.value = [...new Set(all.map(e => e.rule))].sort();
        }
      } catch (e) {}
    }
    function readHash() {
      const m = location.hash.match(/filter=(\w+)/);
      curFilter.value = m ? m[1] : 'all';
      load();
    }
    function clearFilter() {
      location.hash = '#/alerts';
      curFilter.value = 'all';
      load();
    }
    function resetFilter() {
      q.container = ''; q.rule = ''; q.severity = '';
      load();
    }
    onMounted(() => { readHash(); state.timer = setInterval(load, 3000); });
    onUnmounted(() => clearInterval(state.timer));
    window.addEventListener('hashchange', readHash);
    return { events, curFilter, filterLabel, clearFilter, resetFilter, q, ruleOptions,
             openEventDetail, fmtTime, sevTag };
  },
};

/* ================================================================
 * Review queue
 * ================================================================ */
const ReviewPage = {
  template: `
  <div>
    <div class="page-title">人工确认队列 <span class="sub">按容器分组 · 点击展开详情 · 判决联动 main.py</span></div>
    <div v-if="groups.length === 0" class="panel" style="color:var(--muted)">暂无待判决事件 🎉</div>
    <el-collapse v-model="openNames" style="margin-bottom:18px" @change="onExpand">
      <el-collapse-item v-for="g in groups" :key="g.container_id" :name="g.container_id">
        <template #title>
          <div style="display:flex;align-items:center;gap:12px;flex:1;min-width:0">
            <span class="mono" style="font-weight:600">{{ g.container_id }}</span>
            <el-tag size="small" :type="g.event_count > 10 ? 'danger' : 'warning'">{{ g.event_count }} 事件</el-tag>
            <el-tag v-if="g.profile" size="small" type="info" style="max-width:300px;overflow:hidden;text-overflow:ellipsis">
              {{ g.profile.image }} · {{ g.profile.status }}
              <template v-if="g.profile.privileged"> · 特权</template>
            </el-tag>
            <span style="font-size:12px;color:var(--muted)">点击展开明细</span>
          </div>
          <div style="display:flex;align-items:center;gap:8px;margin-right:12px">
            <el-button type="danger" size="small" @click.stop="decide(g, 'confirmed')">确认攻击</el-button>
            <el-button type="success" size="small" @click.stop="decide(g, 'dismissed')">驳回</el-button>
          </div>
        </template>
        <div style="padding:0 4px">
          <el-descriptions v-if="g.profile" :column="3" size="small" border style="margin-bottom:10px">
            <el-descriptions-item label="镜像">{{ g.profile.image }}
              <el-tag size="small" :type="g.profile.runtime === 'k8s' ? 'primary' : 'success'"
                      style="margin-left:6px">{{ g.profile.runtime === 'k8s' ? 'k8s' : 'docker' }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="状态">{{ g.profile.status }}</el-descriptions-item>
            <el-descriptions-item label="特权">{{ g.profile.privileged }}</el-descriptions-item>
            <el-descriptions-item label="端口/IP">{{ g.profile.ports }}</el-descriptions-item>
            <el-descriptions-item label="创建">{{ g.profile.created }}</el-descriptions-item>
            <el-descriptions-item label="PID">{{ g.profile.pid }}</el-descriptions-item>
          </el-descriptions>
          <p v-else style="font-size:12px;color:var(--muted);margin-bottom:10px">画像加载中…</p>
          <el-table :data="g.events" size="small">
            <el-table-column label="时间" width="160"><template #default="{row}">{{ fmtTime(row.timestamp) }}</template></el-table-column>
            <el-table-column label="规则" min-width="170"><template #default="{row}"><span class="ev-rule">{{ row.rule }}</span></template></el-table-column>
            <el-table-column label="进程" width="140"><template #default="{row}">
              <span class="mono">{{ row.event?.comm || '—' }}</span></template></el-table-column>
            <el-table-column label="AI 研判" min-width="200"><template #default="{row}">
              <template v-if="row.ai">
                <el-tag :type="row.ai.ai_verdict === 'true_positive' ? 'danger' : 'success'" size="small">
                  {{ row.ai.ai_verdict === 'true_positive' ? '真实攻击' : '误报' }} {{ row.ai.ai_confidence }}%</el-tag>
                <div style="font-size:12px;color:var(--muted);margin-top:4px">{{ row.ai.ai_report }}</div>
              </template>
              <span v-else style="color:var(--muted)">—</span>
            </template></el-table-column>
          </el-table>
        </div>
      </el-collapse-item>
    </el-collapse>
  </div>`,
  setup() {
    const groups = ref([]);
    const openNames = ref([]);  // 默认全部收起, 点击展开
    async function load() {
      try { groups.value = (await get('/api/review/queue')).groups; } catch (e) {}
    }
    // v0.5.6: 展开才加载画像 (k8s API 慢, 收起态零调用)
    async function onExpand(names) {
      for (const g of groups.value) {
        if (names.includes(g.container_id) && !g.profile) {
          try {
            const r = await get('/api/review/profile?container_id=' + encodeURIComponent(g.container_id));
            g.profile = r.profile;
          } catch (e) {}
        }
      }
    }
    async function decide(g, decision) {
      try {
        await post('/api/review/decision', { container_id: g.container_id, decision, event_count: g.event_count });
        ElMessage.success(decision === 'confirmed' ? '已确认攻击 → 冻结执行中' : '已驳回 → 解冻执行中');
        load();
      } catch (e) { ElMessage.error(e.message); }
    }
    usePolling(load, 3000);
    return { groups, decide, fmtTime, openNames, onExpand };
  },
};

/* ================================================================
 * Behavior log
 * ================================================================ */
const BehaviorPage = {
  template: `
  <div>
    <div class="page-title">行为日志 <span class="sub">全量 syscall (behaviors.log)</span></div>
    <div class="panel" style="display:flex;gap:14px;align-items:center;padding:12px 18px">
      <el-input v-model="q.container" placeholder="容器过滤 (支持模糊)" style="width:220px" clearable @change="load" />
      <el-select v-model="q.syscall" placeholder="系统调用" clearable style="width:140px" @change="load">
        <el-option v-for="t in ['execve','openat','connect','mount','ptrace','capset']" :key="t" :label="t" :value="t" />
      </el-select>
      <el-checkbox v-model="q.hostOnly" @change="load">仅宿主机</el-checkbox>
      <span style="color:var(--muted);font-size:12px">共 {{ events.length }} 条 (最近 500)</span>
    </div>
    <div class="panel">
      <el-table :data="events" size="small" max-height="68vh" @row-click="openEventDetail">
        <el-table-column label="时间" width="165"><template #default="{row}">{{ fmtTime(row.timestamp) }}</template></el-table-column>
        <el-table-column label="容器" width="200"><template #default="{row}"><span class="mono">{{ row.container_id }}</span></template></el-table-column>
        <el-table-column label="类型" width="90"><template #default="{row}">
          <el-tag size="small" type="info">{{ row.event_type }}</el-tag></template></el-table-column>
        <el-table-column label="进程" width="150"><template #default="{row}">
          <span class="mono">{{ row.comm }} ({{ row.pid }})</span></template></el-table-column>
        <el-table-column label="目标" min-width="240"><template #default="{row}">
          <span class="mono">{{ row.target_path || row.daddr || '' }}</span></template></el-table-column>
      </el-table>
    </div>
  </div>`,
  setup() {
    const q = reactive({ container: '', syscall: '', hostOnly: false });
    const events = ref([]);
    async function load() {
      try {
        const p = new URLSearchParams({ limit: 500 });
        if (q.container) p.set('container', q.container);
        if (q.syscall) p.set('syscall', q.syscall);
        if (q.hostOnly) p.set('host_only', 'true');
        events.value = (await get('/api/behaviors?' + p)).events;
      } catch (e) {}
    }
    usePolling(load, 5000);
    return { q, events, load, fmtTime, openEventDetail };
  },
};

/* ================================================================
 * Assets (v0.5.7) — 资产管理: 按节点分组 + 服务关联
 * ================================================================ */
const AssetsPage = {
  template: `
  <div>
    <div class="page-title">资产管理 <span class="sub">监控资产 · 按节点/物理机分组</span></div>
    <div class="panel" style="display:flex;align-items:center;gap:14px;padding:12px 18px">
      <el-tag size="small" type="primary">运行时: {{ data.runtime || '—' }}</el-tag>
      <span style="color:var(--muted);font-size:13px">资产 {{ data.total || 0 }} · 节点 {{ (data.nodes||[]).length }} · 服务 {{ (data.services||[]).length }}</span>
      <el-tag v-if="data.error" size="small" type="danger" style="margin-left:auto">{{ data.error }}</el-tag>
    </div>

    <!-- 拓扑图 (v0.5.7): 蓝色星空背景, 节点=pod, 按 node 成簇, 服务关联连线 -->
    <div class="panel" style="display:flex;align-items:center;gap:12px;padding:10px 18px;flex-wrap:wrap;margin-bottom:0;border-bottom:none;border-radius:10px 10px 0 0">
      <span style="font-size:13px;color:var(--muted)">拓扑筛选:</span>
      <el-select v-model="topoFilter.ns" placeholder="命名空间" clearable size="small" style="width:150px" @change="buildTopoDebounced">
        <el-option v-for="ns in nsOptions" :key="ns" :label="ns" :value="ns" />
      </el-select>
      <el-select v-model="topoFilter.node" placeholder="节点" clearable size="small" style="width:180px" @change="buildTopoDebounced">
        <el-option v-for="nd in data.nodes" :key="nd.name" :label="nd.name" :value="nd.name" />
      </el-select>
      <el-checkbox v-model="topoFilter.showInfra" size="small" @change="buildTopoDebounced">公共服务圈</el-checkbox>
      <el-checkbox v-model="topoFilter.showPrivate" size="small"
                   @change="onPrivateToggle">私有服务圈</el-checkbox>
      <el-select v-model="topoFilter.svc" placeholder="私有服务筛选" clearable size="small"
                 style="width:180px" :disabled="!topoFilter.showPrivate"
                 @change="buildTopoDebounced">
        <el-option v-for="s in privateSvcOptions" :key="s" :label="s" :value="s" />
      </el-select>
    </div>
    <div class="panel topo-stars" style="position:relative;padding:0;overflow:hidden;border-radius:0 0 10px 10px">
      <div ref="topoRef" style="width:100%;height:420px"></div>
      <div style="position:absolute;top:12px;left:16px;font-size:13px;color:#8ea6c8;pointer-events:none">
        <span style="font-weight:600;color:#cbd5e1">资产拓扑</span>
        <span style="margin-left:10px">● 节点=pod · 按物理机成簇 · 橙线=服务关联 · 命名空间着色</span>
      </div>
    </div>

    <div v-for="node in data.nodes" :key="node.name" class="panel">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
        <h3 style="margin:0">🖥️ {{ node.name }}</h3>
        <el-tag size="small" type="info">{{ node.pods.length }} pods</el-tag>
        <span style="font-size:12px;color:var(--muted)">物理机/VM</span>
      </div>
      <el-table :data="node.pods" size="small" stripe @row-click="showPod">
        <el-table-column label="Pod" min-width="220"><template #default="{row}">
          <span class="mono">{{ row.namespace }}/{{ row.name }}</span></template></el-table-column>
        <el-table-column label="镜像" min-width="220"><template #default="{row}">
          <span class="mono" style="font-size:12px">{{ row.images[0] || '—' }}</span></template></el-table-column>
        <el-table-column label="状态" width="110"><template #default="{row}">
          <el-tag size="small" :type="row.status === 'Running' ? 'success' : 'info'">{{ row.status }}</el-tag></template></el-table-column>
        <el-table-column label="Pod IP" width="120"><template #default="{row}">
          <span class="mono">{{ row.pod_ip || '—' }}</span></template></el-table-column>
        <el-table-column label="特权" width="80"><template #default="{row}">
          <el-tag v-if="row.privileged" size="small" type="danger">是</el-tag>
          <span v-else style="color:var(--muted)">否</span></template></el-table-column>
        <el-table-column label="服务" min-width="140"><template #default="{row}">
          <el-tag v-for="s in row.services" :key="s" size="small" type="warning" style="margin-right:4px">{{ s }}</el-tag>
          <span v-if="!row.services.length" style="color:var(--muted)">—</span></template></el-table-column>
        <el-table-column label="Labels" min-width="180"><template #default="{row}">
          <span style="font-size:12px;color:var(--muted)">{{ Object.entries(row.labels).slice(0,3).map(([k,v]) => k+'='+v).join(' ') || '—' }}</span></template></el-table-column>
      </el-table>
    </div>

    <div class="panel">
      <h3>服务暴露</h3>
      <el-table :data="data.services" size="small" stripe>
        <el-table-column prop="name" label="Service" min-width="160" />
        <el-table-column prop="namespace" label="命名空间" width="140" />
        <el-table-column prop="type" label="类型" width="120" />
        <el-table-column prop="cluster_ip" label="Cluster IP" width="140" />
        <el-table-column label="端口" min-width="140"><template #default="{row}">
          <span class="mono">{{ row.ports.join(', ') || '—' }}</span></template></el-table-column>
        <el-table-column label="Selector" min-width="180"><template #default="{row}">
          <span style="font-size:12px;color:var(--muted)">{{ Object.entries(row.selector).map(([k,v]) => k+'='+v).join(' ') || '—' }}</span></template></el-table-column>
      </el-table>
    </div>

    <el-dialog v-model="podDialog.show" :title="podDialog.title" width="560px">
      <template v-if="podDialog.pod">
        <el-descriptions :column="2" size="small" border>
          <el-descriptions-item label="命名空间">{{ podDialog.pod.namespace }}</el-descriptions-item>
          <el-descriptions-item label="节点">{{ podDialog.pod.node }}</el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag size="small" :type="podDialog.pod.status === 'Running' ? 'success' : 'info'">{{ podDialog.pod.status }}</el-tag></el-descriptions-item>
          <el-descriptions-item label="Pod IP"><span class="mono">{{ podDialog.pod.pod_ip || '—' }}</span></el-descriptions-item>
          <el-descriptions-item label="特权">{{ podDialog.pod.privileged ? '是' : '否' }}</el-descriptions-item>
          <el-descriptions-item label="创建">{{ podDialog.pod.created }}</el-descriptions-item>
          <el-descriptions-item label="镜像" :span="2">
            <span v-for="img in podDialog.pod.images" :key="img" class="mono" style="display:block;font-size:12px">{{ img }}</span></el-descriptions-item>
          <el-descriptions-item label="所属服务" :span="2">
            <el-tag v-for="s in podDialog.pod.services" :key="s" size="small" type="warning" style="margin-right:4px">{{ s }}</el-tag>
            <span v-if="!podDialog.pod.services.length" style="color:var(--muted)">—</span></el-descriptions-item>
          <el-descriptions-item label="Labels" :span="2">
            <div style="font-size:12px;color:var(--muted)">
              <div v-for="(v,k) in podDialog.pod.labels" :key="k" class="mono">{{ k }} = {{ v }}</div>
            </div></el-descriptions-item>
        </el-descriptions>
      </template>
    </el-dialog>
  </div>`,
  setup() {
    const data = reactive({ runtime: '', total: 0, nodes: [], services: [], error: '' });
    const podDialog = reactive({ show: false, pod: null, title: '' });
    const topoRef = ref(null);
    let chart = null;
    let lastTopoKey = '';  // 轮询去重: 数据未变不重建图 (布局稳定)

    // v0.5.7: 拓扑图 — ECharts 关系图
    //  节点=pod (按命名空间着色) + service (金色菱形)
    //  按 node 成簇; 公共依赖服务 (kube-dns/metrics-server) 默认折叠连线
    //  筛选: 命名空间/节点/仅服务关联
    const topoFilter = reactive({ ns: '', node: '', showInfra: false, showPrivate: false, svc: '' });
    const nsOptions = ref([]);
    const privateSvcOptions = ref([]);
    const INFRA_SVCS = ['kube-dns', 'metrics-server'];
    const NS_COLORS = {
      'default': '#3b82f6', 'kube-system': '#22c55e',
      'kube-public': '#f59e0b', 'kube-node-lease': '#a855f7',
    };

    function buildTopo() {
      if (!topoRef.value || typeof echarts === 'undefined') return;
      if (!chart) chart = echarts.init(topoRef.value);
      const nodes = [];
      const nodeIdx = {};
      const svcIdx = {};
      // 筛选: 过滤 pod
      const nodeGroups = [];
      const filteredNodes = data.nodes
        .filter(nd => !topoFilter.node || nd.name === topoFilter.node)
        .map(nd => {
          const pods = nd.pods.filter(p =>
            (!topoFilter.ns || p.namespace === topoFilter.ns));
          if (pods.length) nodeGroups.push(nd.name);
          return { name: nd.name, pods };
        })
        .filter(nd => nd.pods.length > 0);
      filteredNodes.forEach(nd => {
        nd.pods.forEach(p => {
          const key = p.namespace + '/' + p.name;
          nodeIdx[key] = nodes.length;
          nodes.push({
            id: key, name: p.name.split('-')[0],
            symbolSize: p.privileged ? 34 : 24,
            category: nodeGroups.indexOf(nd.name),
            itemStyle: { color: NS_COLORS[p.namespace] || '#64748b' },
            __pod: p,
          });
        });
      });
      data.services.forEach(s => {
        if (topoFilter.ns && s.namespace !== topoFilter.ns) return;
        const sk = s.namespace + '/' + s.name;
        svcIdx[sk] = nodes.length;
        nodes.push({
          id: sk, name: s.name, symbol: 'diamond', symbolSize: 18,
          category: -1,
          itemStyle: { color: '#f59e0b' },
        });
      });
      // 手动布局 (layout:'none'): 按 node 分组圆周排列 — 零布局计算
      // 注意: layout:'none' 的 x/y 是像素 (相对容器左上), 非百分比!
      const topoW = topoRef.value.clientWidth || 800;
      const topoH = topoRef.value.clientHeight || 420;
      const groups = filteredNodes.map(nd => nd.name);
      // 服务关联 pod 发光 (跟随节点, 不同服务不同色) — 替代 graphic 圈
      // (graphic circle 坐标系与 roam 变换不同步, 圈不跟随 pod)
      // v0.5.7: 公共/私有独立开关 + 私有服务筛选 (svc 选中只高亮该服务)
      const svcColors = ['#f59e0b', '#22c55e', '#a855f7', '#06b6d4', '#f43f5e'];
      const svcColorIdx = {};
      const privateSvcs = new Set();
      filteredNodes.forEach(nd => nd.pods.forEach(p => {
        if (!p.services.length) return;
        const sk = p.namespace + '/' + p.services[0];
        if (!(sk in svcColorIdx)) svcColorIdx[sk] = Object.keys(svcColorIdx).length;
        if (!INFRA_SVCS.includes(p.services[0])) privateSvcs.add(p.services[0]);
        const idx = nodeIdx[p.namespace + '/' + p.name];
        if (idx !== undefined) {
          const isInfra = INFRA_SVCS.includes(p.services[0]);
          // v0.5.7: 私有服务筛选独立生效 (选了就高亮, 不依赖 showPrivate 开关)
          const svcSelected = topoFilter.svc === p.services[0];
          const show = isInfra ? topoFilter.showInfra
                      : (svcSelected || topoFilter.showPrivate);
          if (show) {
            nodes[idx].itemStyle.shadowColor =
              svcColors[svcColorIdx[sk] % svcColors.length];
            nodes[idx].itemStyle.shadowBlur = 25;
          }
        }
      }));
      // 私有服务下拉选项
      privateSvcOptions.value = [...privateSvcs].sort();
      // 服务图例 (左下角, 随开关出现): 只显示被激活的服务
      const legendItems = Object.entries(svcColorIdx).map(([sk, i]) => {
        const svcName = sk.split('/')[1];
        const isInfra = INFRA_SVCS.includes(svcName);
        // svc 选中时该服务图例独立显示 (不依赖 showPrivate)
        const active = isInfra ? topoFilter.showInfra
                      : (topoFilter.showPrivate || topoFilter.svc === svcName);
        return active ? {
          text: (isInfra ? '公共 ' : '私有 ') + svcName,
          color: svcColors[i % svcColors.length],
        } : null;
      }).filter(Boolean);
      const legendGraphics = legendItems.map((it, i) => ({
        type: 'group',
        id: 'svc-legend-' + i,   // 稳定 id: ECharts graphic 按 id 合并, 空数组时旧图例被清
        left: 12 + i * 150, bottom: 8,
        children: [
          { type: 'circle', shape: { r: 4 },
            style: { fill: it.color }, left: 0, top: 2 },
          { type: 'text', left: 10, top: 0,
            style: { text: it.text, fill: '#8ea6c8', fontSize: 11 } },
        ],
      }));
      groups.forEach((g, gi) => {
        const pods = filteredNodes[gi].pods;
        const angle = (2 * Math.PI * gi) / Math.max(groups.length, 1) - Math.PI / 2;
        const cx = topoW * 0.5 + topoW * 0.28 * Math.cos(angle);
        const cy = topoH * 0.5 + topoH * 0.3 * Math.sin(angle);
        const n = pods.length;
        pods.forEach((p, pi) => {
          const key = p.namespace + '/' + p.name;
          const idx = nodeIdx[key];
          if (idx === undefined) return;
          const pa = (2 * Math.PI * pi) / Math.max(n, 1);
          nodes[idx].x = cx + 70 * Math.cos(pa);
          nodes[idx].y = cy + 50 * Math.sin(pa);
        });
      });
      // service 节点放中间 (像素坐标)
      Object.entries(svcIdx).forEach(([sk, idx]) => {
        nodes[idx].x = topoW * 0.5;
        nodes[idx].y = topoH * 0.5;
      });
      const key = JSON.stringify({ nodes: nodes.map(n => n.id + n.symbolSize + (n.category||'') + (n.itemStyle?.shadowColor||'')),
                                    legend: legendGraphics.map(g => JSON.stringify(g.children)),
                                    svc: topoFilter.svc });
      if (key === lastTopoKey) return;
      lastTopoKey = key;
      // 首次全量配置, 之后增量更新 data
      if (!chart.__topoInit) {
        chart.setOption({
          backgroundColor: 'transparent',
          tooltip: { trigger: 'item',
            formatter: (p) => p.data?.__pod
              ? `${p.data.__pod.namespace}/${p.data.__pod.name}\n状态: ${p.data.__pod.status}\n服务: ${p.data.__pod.services.join(',') || '无'}`
              : (p.data.id || p.name) },
          graphic: legendGraphics,
          series: [{
            type: "graph", layout: "none", roam: true, draggable: false,
            label: { show: true, fontSize: 10, color: '#cbd5e1' },
            animation: false,
            emphasis: { focus: 'adjacency' },
          }],
        }, { replaceMerge: ['graphic'] });
        chart.__topoInit = true;
        // 点击节点 → pod 详情
        chart.off('click');
        chart.on('click', (params) => {
          if (params.data && params.data.__pod) {
            showPod(params.data.__pod);
          }
        });
      }
      chart.setOption({
        legend: { data: groups, textStyle: { color: '#8ea6c8' },
                  bottom: 4, itemWidth: 12, itemHeight: 12 },
        graphic: legendGraphics,
        series: [{
          type: "graph", layout: "none", roam: true, draggable: false,
          label: { show: true, fontSize: 10, color: '#cbd5e1' },
          animation: false,
          categories: groups.map(n => ({ name: n })),
          data: nodes,
          links: [],
        }],
      }, { replaceMerge: ['graphic'] });  // 清空旧 graphic (图例随开关消失)
    }

    // v0.5.7: 关闭私有服务圈时清空筛选 + 重建图 (筛选是开关子功能)
    function onPrivateToggle() {
      if (!topoFilter.showPrivate) topoFilter.svc = '';
      buildTopoDebounced();
    }

    // v0.5.7: 筛选防抖 — 快速连续筛选合并为一次重绘 (响应感知更快)
    let topoDebounce = null;
    function buildTopoDebounced() {
      clearTimeout(topoDebounce);
      topoDebounce = setTimeout(() => buildTopo(), 150);
    }

    async function load() {
      try {
        Object.assign(data, await get('/api/assets'));
        // 命名空间选项
        const nss = new Set();
        data.nodes.forEach(nd => nd.pods.forEach(p => nss.add(p.namespace)));
        nsOptions.value = [...nss].sort();
        buildTopo();
      } catch (e) {}
    }
    function showPod(row) {
      podDialog.pod = row;
      podDialog.title = row.namespace + '/' + row.name;
      podDialog.show = true;
    }
    onMounted(() => {
      load();
      state.timer = setInterval(load, 5000);
      window.addEventListener('resize', () => chart && chart.resize());
    });
    onUnmounted(() => {
      clearInterval(state.timer);
      if (chart) { chart.dispose(); chart = null; }
    });
    return { data, podDialog, showPod, topoRef, topoFilter, nsOptions,
             privateSvcOptions, buildTopoDebounced, onPrivateToggle };
  },
};

/* ================================================================
 * Attack Chain (v0.5.8) — 攻击链流程图 (方框箭头, ECharts)
 * ================================================================ */
const AttackChainPage = {
  template: `
  <div>
    <div class="page-title">攻击链分析 <span class="sub">行为时间窗 → 分阶段还原攻击步骤</span></div>
    <div v-if="err" class="panel" style="color:var(--warn)">{{ err }}</div>
    <div v-else-if="steps.length === 0" class="panel" style="color:var(--muted)">该时间窗无攻击链数据</div>
    <template v-else>
      <!-- v0.5.8: 被攻击目标画像 -->
      <div class="panel" style="margin-bottom:14px">
        <h3 style="margin-bottom:10px">🎯 被攻击目标 <span class="sub" style="font-size:12px;color:var(--muted)">容器/服务画像</span></h3>
        <el-descriptions v-if="target" :column="4" size="small" border>
          <el-descriptions-item label="容器"><span class="mono">{{ target.name }}</span></el-descriptions-item>
          <el-descriptions-item label="镜像">{{ target.image }}</el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag size="small" :type="target.status === 'Running' ? 'success' : 'info'">{{ target.status }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="特权">{{ target.privileged ? '是' : '否' }}</el-descriptions-item>
          <el-descriptions-item label="IP/端口"><span class="mono">{{ target.ports }}</span></el-descriptions-item>
          <el-descriptions-item label="运行时">
            <el-tag size="small" :type="target.runtime === 'k8s' ? 'primary' : 'success'">{{ target.runtime }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="创建">{{ target.created }}</el-descriptions-item>
          <el-descriptions-item label="告警时间"><span class="mono">{{ alert.ts }}</span></el-descriptions-item>
        </el-descriptions>
        <p v-else style="font-size:12px;color:var(--muted)">目标容器画像不可用 (已删除或无法查询)</p>
      </div>
      <div class="panel">
        <h3 style="margin-bottom:10px">
          🕸️ 攻击链
          <el-tag size="small" type="danger" style="margin-left:8px">{{ steps.length }} 阶段</el-tag>
        </h3>
        <div ref="chainRef" style="width:100%;height:300px"></div>
        <div style="margin-top:10px;font-size:12px;color:var(--muted)">
          <el-tag v-for="(c, i) in phaseColors" :key="i" size="small" style="margin-right:8px"
                  :color="c.color" effect="plain">{{ c.name }}</el-tag>
        </div>
      </div>
      <div class="panel">
        <h3 style="margin-bottom:10px">阶段详情</h3>
        <el-table :data="steps" size="small" stripe>
          <el-table-column label="阶段" width="110"><template #default="{row}">
            <el-tag size="small" :color="row.color" effect="dark" style="border:none;color:#fff">{{ row.phase }}</el-tag>
          </template></el-table-column>
          <el-table-column label="相对时间" width="120"><template #default="{row}">
            <div class="mono">{{ row.rel === row.end_rel ? row.rel + 's' : row.rel + 's ~ ' + row.end_rel + 's' }}</div>
            <div class="mono" style="font-size:11px;color:var(--muted)">
              {{ (row.abs_start || '').replace('T',' ').slice(5,19) }}</div>
          </template></el-table-column>
          <el-table-column label="关键事件" min-width="300"><template #default="{row}">
            <div v-for="e in row.events.slice(0,3)" :key="e.ts + e.pid" style="font-size:12px" class="mono">
              {{ e.event_type }} {{ e.comm }} {{ e.target || '' }}</div>
            <span v-if="row.events.length > 3" style="font-size:11px;color:var(--muted)">+{{ row.events.length - 3 }} 更多</span>
          </template></el-table-column>
          <el-table-column label="事件数" width="80"><template #default="{row}">
            <span class="mono">{{ row.events.length }}</span></template></el-table-column>
        </el-table>
      </div>
    </template>
  </div>`,
  setup() {
    const steps = ref([]);
    const alert = ref({});
    const err = ref('');
    const target = ref(null);   // 被攻击目标画像 (v0.5.8)
    const chainRef = ref(null);
    const phaseColors = [
      { name: '侦查探测', color: '#3b82f6' }, { name: '提权逃逸', color: '#ef4444' },
      { name: '利用执行', color: '#f59e0b' }, { name: '外联 C2', color: '#a855f7' },
      { name: '窃取数据', color: '#06b6d4' },
    ];
    let chart = null;

    async function load() {
      // 兼容 #/chain? 与 #chain? 两种 hash
      const m = location.hash.match(/\/?chain\?container=([^&]+)&ts=([^&]+)/);
      if (!m) { err.value = '缺少攻击链参数'; return; }
      const container = decodeURIComponent(m[1]);
      const ts = decodeURIComponent(m[2]);
      try {
        const d = await get('/api/attack-chain?container=' + encodeURIComponent(container) +
                            '&ts=' + encodeURIComponent(ts));
        if (d.error) { err.value = d.error; return; }
        steps.value = d.steps || [];
        alert.value = d.alert || {};
        // v0.5.8: 被攻击目标画像
        try {
          const prof = await get('/api/review/profile?container_id=' +
                                 encodeURIComponent(container));
          target.value = prof.profile;
        } catch (e) { target.value = null; }
        // v-else 分支渲染后 chainRef 才就绪 — nextTick 再画图
        Vue.nextTick(() => renderChart());
      } catch (e) { err.value = e.message; }
    }

    // 方框箭头流程图: 长条矩形横向排布, 箭头连接, 阶段着色
    function renderChart() {
      if (!chainRef.value || typeof echarts === 'undefined') return;
      if (!chart) chart = echarts.init(chainRef.value);
      const nodes = steps.value.map((s, i) => {
        // 关键命令: 该阶段第一个非空 comm+target
        const first = s.events[0] || {};
        const cmd = `${first.comm || ''} ${(first.target || '').slice(0, 20)}`.trim();
        const timeTxt = s.rel === s.end_rel ? `${s.rel}s` : `${s.rel}s~${s.end_rel}s`;
        // 本地绝对时间 (behaviors 时间戳已是本地)
        const absTxt = (s.abs_start || '').replace('T', ' ').slice(5, 19);
        const labelLines = [s.phase, timeTxt];
        if (absTxt) labelLines.push(absTxt);
        if (cmd) labelLines.push(cmd);
        return {
          id: 's' + i, name: s.phase,
          symbol: 'rect',
          symbolSize: [150, 66],   // 长条矩形 (容纳4行)
          x: 10 + i * 170, y: 40,
          itemStyle: { color: s.color, borderRadius: 4 },
          label: { show: true, color: '#fff', fontSize: 11,
                   formatter: labelLines.join('\n'),
                   lineHeight: 15 },
          __idx: i,
        };
      });
      const edges = steps.value.slice(1).map((_, i) => ({
        source: 's' + i, target: 's' + (i + 1),
      }));
      chart.setOption({
        tooltip: { trigger: 'item',
          formatter: (p) => {
            if (p.dataType === 'edge') return '';
            const s = steps.value[p.data.__idx];
            const relTxt = s.rel === s.end_rel ? `${s.rel}s` : `${s.rel}s~${s.end_rel}s`;
            return `<b>${s.phase}</b> (${relTxt})<br>` +
              s.events.slice(0, 4).map(e =>
                `${e.event_type} ${e.comm} ${e.target || ''}`).join('<br>');
          } },
        series: [{
          type: 'graph', layout: 'none', roam: true, draggable: false,
          label: { show: true },
          edgeSymbol: ['none', 'arrow'], edgeSymbolSize: 10,
          lineStyle: { color: '#8ea6c8', width: 2 },
          data: nodes, links: edges,
        }],
      });
      chart.off('click');
      chart.on('click', (p) => {
        if (p.data && p.data.__idx !== undefined) {
          const s = steps.value[p.data.__idx];
          ElMessageBox.alert(
            s.events.map(e =>
              `<div class="mono" style="font-size:12px;margin:4px 0">${e.rel}s ${e.event_type} ${e.comm} ${e.target || ''}</div>`
            ).join(''),
            `${s.phase} 事件详情 (${s.events.length} 条)`,
            { dangerouslyUseHTMLString: true, confirmButtonText: '关闭' });
        }
      });
    }

    onMounted(() => { load(); window.addEventListener('hashchange', load); });
    onUnmounted(() => {
      window.removeEventListener('hashchange', load);
      if (chart) { chart.dispose(); chart = null; }
    });
    return { steps, alert, err, target, chainRef, phaseColors };
  },
};

/* ================================================================
 * Rules
 * ================================================================ */
const RulesPage = {
  template: `
  <div>
    <div class="page-title">检测规则 <span class="sub">rules.yaml · guard 3s 热加载</span></div>
    <div class="panel" style="display:flex;justify-content:space-between;align-items:center">
      <span style="color:var(--muted)">共 {{ rules.length }} 条规则</span>
      <el-button type="primary" size="small" @click="showAdd = true">添加规则</el-button>
    </div>
    <div class="panel">
      <el-table :data="rules" size="small" stripe>
        <el-table-column label="名称" min-width="180"><template #default="{row}">
          <span class="ev-rule">{{ row.name }}</span></template></el-table-column>
        <el-table-column label="严重度" width="100"><template #default="{row}">
          <el-tag :type="sevTag(row.severity)" size="small">{{ row.severity }}</el-tag></template></el-table-column>
        <el-table-column label="事件类型" width="100"><template #default="{row}">
          <span class="mono">{{ row.event_type }}</span></template></el-table-column>
        <el-table-column label="攻击向量" width="140"><template #default="{row}">
          <span class="mono">{{ row.attack_vector }}</span></template></el-table-column>
        <el-table-column label="描述" min-width="200"><template #default="{row}">{{ row.description }}</template></el-table-column>
        <el-table-column label="来源" width="130"><template #default="{row}">
          <el-tag v-if="row.added_source === 'ai_suggestion'" size="small" type="primary">AI 建议</el-tag>
          <el-tag v-else-if="row.added_source === 'manual'" size="small" type="warning">手动</el-tag>
          <span v-else style="color:var(--muted)">—</span>
        </template></el-table-column>
        <el-table-column label="操作者" width="110"><template #default="{row}">
          <span class="mono">{{ row.added_by }}</span></template></el-table-column>
        <el-table-column label="入库时间" width="160"><template #default="{row}">
          <span style="color:var(--muted)">{{ row.added_at }}</span></template></el-table-column>
        <el-table-column label="动作" width="110"><template #default="{row}">
          <span class="mono">{{ row.action }}</span></template></el-table-column>
      </el-table>
    </div>

    <el-dialog v-model="showAdd" title="添加规则 (条件表单)" width="640px">
      <el-form label-width="90px" size="small">
        <el-form-item label="名称"><el-input v-model="newRule.name" placeholder="suspicious_xxx" /></el-form-item>
        <el-form-item label="严重度">
          <el-select v-model="newRule.severity" style="width:160px">
            <el-option v-for="s in ['CRITICAL','HIGH','MEDIUM','LOW']" :key="s" :label="s" :value="s" /></el-select>
        </el-form-item>
        <el-form-item label="事件类型">
          <el-select v-model="newRule.event_type" style="width:160px">
            <el-option v-for="t in ['execve','openat','connect','mount','ptrace','capset']" :key="t" :label="t" :value="t" /></el-select>
        </el-form-item>
        <el-form-item label="攻击向量"><el-input v-model="newRule.attack_vector" placeholder="custom_vector" /></el-form-item>
        <el-form-item label="描述"><el-input v-model="newRule.description" /></el-form-item>
        <el-form-item label="条件 (AND)">
          <div v-for="(row, i) in condRows" :key="i" style="display:flex;gap:8px;margin-bottom:8px;width:100%">
            <el-input v-model="row.field" placeholder="字段 (comm/target_path/uid...)" style="width:200px" />
            <el-select v-model="row.op" style="width:110px">
              <el-option v-for="op in ['==','neq','startswith','endswith','contains','glob']" :key="op" :label="op" :value="op" /></el-select>
            <el-input v-model="row.value" placeholder="值 (逗号=OR)" style="flex:1" />
            <el-button circle size="small" @click="condRows.splice(i,1)">✕</el-button>
          </div>
          <el-button size="small" @click="condRows.push({field:'',op:'==',value:''})">+ 条件行</el-button>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button size="small" @click="showAdd = false">取消</el-button>
        <el-button type="primary" size="small" :loading="saving" @click="submitRule">提交 (热加载 3s 生效)</el-button>
      </template>
    </el-dialog>
  </div>`,
  setup() {
    const rules = ref([]);
    const showAdd = ref(false);
    const saving = ref(false);
    const newRule = reactive({ name: '', severity: 'HIGH', event_type: 'execve', attack_vector: '', description: '' });
    const condRows = ref([{ field: '', op: '==', value: '' }]);
    async function load() {
      try { rules.value = (await get('/api/rules')).rules; } catch (e) {}
    }
    async function submitRule() {
      if (!newRule.name || !newRule.event_type) { ElMessage.warning('名称和事件类型必填'); return; }
      const condition = { all: [] };
      condRows.value.forEach(r => {
        if (!r.field || !r.value) return;
        const v = r.value.includes(',') ? r.value.split(',').map(s => s.trim()) : r.value.trim();
        condition.all.push(r.op === '==' ? { [r.field]: v } : { [r.field]: { [r.op]: v } });
      });
      if (condition.all.length === 0) { ElMessage.warning('至少一个条件行'); return; }
      saving.value = true;
      try {
        await post('/api/rules', { rule: { ...newRule, condition }, source: 'manual' });
        ElMessage.success('规则已添加 (3s 内热加载)');
        showAdd.value = false;
        newRule.name = ''; newRule.attack_vector = ''; newRule.description = '';
        condRows.value = [{ field: '', op: '==', value: '' }];
        load();
      } catch (e) { ElMessage.error(e.message); }
      saving.value = false;
    }
    usePolling(load, 3000);
    return { rules, showAdd, saving, newRule, condRows, submitRule, sevTag };
  },
};

/* ================================================================
 * AI suggested rules
 * ================================================================ */
const AiRulesPage = {
  template: `
  <div>
    <div class="page-title">AI 建议规则 <span class="sub">ai_results.log 中模型发现的未知攻击模式</span></div>
    <div v-if="items.length === 0" class="panel" style="color:var(--muted)">暂无 AI 建议</div>
    <div v-for="it in items" :key="it.event_ts" class="panel">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
        <div>
          <span class="ev-rule">{{ it.suggested_rule?.name || '未命名规则' }}</span>
          <el-tag size="small" style="margin-left:10px" type="info">{{ it.suggested_rule?.severity }}</el-tag>
          <span style="color:var(--muted);font-size:12px;margin-left:10px">{{ fmtTime(it.event_ts) }}</span>
        </div>
        <div>
          <el-button type="primary" size="small" @click="decide(it, 'confirmed')">确认入库</el-button>
          <el-button size="small" @click="decide(it, 'dismissed')">拒绝</el-button>
        </div>
      </div>
      <el-descriptions :column="2" size="small" border>
        <el-descriptions-item label="描述">{{ it.suggested_rule?.description }}</el-descriptions-item>
        <el-descriptions-item label="事件类型">{{ it.suggested_rule?.event_type }}</el-descriptions-item>
        <el-descriptions-item label="来源容器">{{ it.container_id }}</el-descriptions-item>
        <el-descriptions-item label="AI 报告">{{ it.ai_report }}</el-descriptions-item>
      </el-descriptions>
    </div>
  </div>`,
  setup() {
    const items = ref([]);
    async function load() {
      try { items.value = (await get('/api/ai-rules')).suggestions; } catch (e) {}
    }
    async function decide(it, decision) {
      try {
        await post('/api/ai-rules/decision', { event_ts: it.event_ts, decision, rule: it.suggested_rule });
        ElMessage.success(decision === 'confirmed' ? '规则已入库 (3s 热加载)' : '已拒绝');
        load();
      } catch (e) { ElMessage.error(e.message); }
    }
    usePolling(load, 5000);
    return { items, decide, fmtTime };
  },
};

/* ================================================================
 * Settings
 * ================================================================ */
const SettingsPage = {
  template: `
  <div>
    <div class="page-title">设置</div>

    <div class="panel"><h3>修改密码</h3>
      <el-form :model="pw" label-width="90px" size="small" style="max-width:420px">
        <el-form-item label="旧密码"><el-input v-model="pw.old" type="password" show-password /></el-form-item>
        <el-form-item label="新密码"><el-input v-model="pw.new1" type="password" show-password /></el-form-item>
        <el-form-item label="确认新密码"><el-input v-model="pw.new2" type="password" show-password /></el-form-item>
        <el-button type="primary" size="small" @click="changePw">修改</el-button>
      </el-form>
    </div>

    <div class="panel"><h3>AI 研判配置 <span class="sub">多配置管理 · 获取模型后下拉选择 · 激活切换 (guard 3s 热加载)</span></h3>
      <el-form label-width="120px" size="small" style="max-width:640px">
        <el-form-item label="配置名"><el-input v-model="ai.name" placeholder="如 deepseek / qwen / gpt" /></el-form-item>
        <el-form-item label="Base URL"><el-input v-model="ai.base_url" placeholder="https://api.deepseek.com/v1" /></el-form-item>
        <el-form-item label="API Key"><el-input v-model="ai.api_key" type="password" show-password
          :placeholder="masked || '留空保留现有'" /></el-form-item>
        <el-form-item label="模型">
          <div style="display:flex;gap:8px;width:100%">
            <el-input v-model="ai.model" placeholder="deepseek-chat" style="flex:1" />
            <el-button size="small" :loading="loadingModels" @click="fetchModels">获取模型</el-button>
          </div>
          <el-select v-if="modelOptions.length" v-model="ai.model" placeholder="选择模型" size="small"
                     style="width:100%;margin-top:6px" @change="ai.model = $event">
            <el-option v-for="m in modelOptions" :key="m" :label="m" :value="m" />
          </el-select>
        </el-form-item>
        <el-form-item label="自动响应阈值"><el-input-number v-model="ai.auto_response_threshold" :min="0" :max="100" /></el-form-item>
        <el-form-item label="待审阈值"><el-input-number v-model="ai.pending_review_threshold" :min="0" :max="100" /></el-form-item>
        <el-button type="primary" size="small" @click="saveAiProfile">保存配置</el-button>
        <span style="margin-left:10px;font-size:12px;color:var(--muted)">保存后可在下方列表激活</span>
      </el-form>

      <div style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px">
        <h4 style="margin-bottom:10px">已保存配置</h4>
        <el-table :data="profiles" size="small" stripe>
          <el-table-column label="名称" min-width="120"><template #default="{row}">
            <span class="mono" style="font-weight:600">{{ row.name }}</span>
            <el-tag v-if="row.active" size="small" type="success" style="margin-left:8px">当前使用</el-tag></template></el-table-column>
          <el-table-column prop="base_url" label="Base URL" min-width="200" />
          <el-table-column prop="model" label="模型" width="150" />
          <el-table-column prop="api_key_masked" label="Key" width="100" />
          <el-table-column label="操作" width="160"><template #default="{row}">
            <el-button v-if="!row.active" size="small" type="primary" @click="activateProfile(row)">激活</el-button>
            <el-button size="small" type="danger" @click="deleteProfile(row)">删除</el-button></template></el-table-column>
        </el-table>
      </div>
    </div>

    <div v-if="isAdmin" class="panel"><h3>成员管理</h3>
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <span style="color:var(--muted)">共 {{ users.length }} 个账号</span>
        <el-button type="primary" size="small" @click="showAdd = true">添加成员</el-button>
      </div>
      <el-table :data="users" size="small" stripe>
        <el-table-column prop="username" label="用户名" min-width="160" />
        <el-table-column label="角色" width="120"><template #default="{row}">
          <el-tag size="small" :type="ROLE_TYPES[row.role] || 'info'"
                  :color="ROLE_COLORS[row.role] || ''"
                  :style="ROLE_COLORS[row.role] ? 'color:#fff;border:none' : ''">
            {{ ROLE_LABELS[row.role] || row.role }}</el-tag></template></el-table-column>
        <el-table-column prop="created" label="创建时间" width="200" />
      </el-table>
    </div>

    <div v-if="isAdmin" class="panel"><h3>临时授权 Token</h3>
      <div style="display:flex;gap:10px;align-items:center;margin-bottom:12px;flex-wrap:wrap">
        <el-select v-model="tokenPurpose" style="width:150px" size="small">
          <el-option label="add_member" value="add_member" />
          <el-option label="add_rule" value="add_rule" />
        </el-select>
        <el-select v-model="tokenFor" placeholder="授权给谁" clearable size="small" style="width:150px">
          <el-option v-for="u in eligibleUsers" :key="u.username" :label="u.username" :value="u.username" />
        </el-select>
        <el-input-number v-model="tokenTtl" :min="60" :max="300" :step="30" size="small" />
        <el-input v-model="tokenNote" placeholder="备注 (用途说明)" size="small" style="width:220px" clearable />
        <el-button type="primary" size="small" @click="issueToken">签发</el-button>
        <el-input v-model="issuedToken" readonly size="small" style="width:240px" placeholder="签发后显示" />
      </div>
      <el-table :data="tokens" size="small">
        <el-table-column prop="token" label="Token (前 8 位)" width="130" />
        <el-table-column prop="purpose" label="用途" width="110" />
        <el-table-column prop="grantor" label="签发人" width="100" />
        <el-table-column label="备注" min-width="160">
          <template #default="{row}">
            <span v-if="row.for_user" class="mono" style="margin-right:4px">→{{ row.for_user }}</span>
            <span v-if="row.note" style="color:var(--muted)">{{ row.note }}</span>
            <span v-if="!row.for_user && !row.note" style="color:var(--muted)">—</span>
          </template>
        </el-table-column>
        <el-table-column label="过期" width="200"><template #default="{row}">{{ fmtTs(row.expires) }}</template></el-table-column>
      </el-table>
    </div>

    <el-dialog v-model="showAdd" title="添加成员" width="400px">
      <el-form label-width="80px" size="small">
        <el-form-item label="用户名"><el-input v-model="f.username" /></el-form-item>
        <el-form-item label="密码"><el-input v-model="f.password" type="password" show-password placeholder="至少 6 位" /></el-form-item>
        <el-form-item label="角色">
          <el-select v-model="f.role" style="width:160px">
            <el-option label="管理员 admin" value="admin" />
            <el-option label="运维 operator" value="operator" />
            <el-option label="分析员 analyst" value="analyst" /></el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button size="small" @click="showAdd = false">取消</el-button>
        <el-button type="primary" size="small" @click="addUser">创建 (首登需改密)</el-button>
      </template>
    </el-dialog>
  </div>`,
  setup() {
    const me = JSON.parse(localStorage.getItem('guard_me') || '{}');
    const isAdmin = computed(() => me.role === 'admin');
    const pw = reactive({ old: '', new1: '', new2: '' });
    const ai = reactive({ name: '', model: '', base_url: '', api_key: '', auto_response_threshold: 85, pending_review_threshold: 60 });
    const masked = ref('');
    const profiles = ref([]);
    const modelOptions = ref([]);
    const loadingModels = ref(false);
    const tokenPurpose = ref('add_member');
    const tokenTtl = ref(180);
    const tokenFor = ref('');   // 授权给谁 (成员下拉)
    const tokenNote = ref('');
    const issuedToken = ref('');
    const tokens = ref([]);
    // 成员管理 (v0.5.7: 从独立页并入设置)
    const users = ref([]);
    // v0.5.7: 可授权对象 = 排除自己 + 同/高权限角色 (后端仍校验兜底)
    const eligibleUsers = computed(() => {
      const myRole = me.role;
      return users.value.filter(u =>
        u.username !== me.username &&
        ROLE_RANK[u.role] < ROLE_RANK[myRole]);
    });
    const showAdd = ref(false);
    const f = reactive({ username: '', password: '', role: 'analyst' });

    async function load() {
      try {
        // v0.5.7: 从 profiles 加载 (源), ai_config 仅快照
        const prof = await get('/api/ai/profiles');
        profiles.value = prof.profiles || [];
        const active = prof.profiles?.find(p => p.active) || prof.profiles?.[0];
        if (active) {
          ai.name = active.name;
          ai.model = active.model || '';
          ai.base_url = active.base_url || '';
          masked.value = active.api_key_masked || '';
          if (active.auto_response_threshold) ai.auto_response_threshold = active.auto_response_threshold;
          if (active.pending_review_threshold) ai.pending_review_threshold = active.pending_review_threshold;
        }
      } catch (e) {}
      if (isAdmin.value) {
        try { tokens.value = (await get('/api/tokens/list')).tokens; } catch (e) {}
        try { users.value = (await get('/api/members')).users; } catch (e) {}
      }
    }
    // v0.5.7: 获取模型列表
    async function fetchModels() {
      if (!ai.base_url) { ElMessage.warning('先填 Base URL'); return; }
      loadingModels.value = true;
      try {
        const r = await post('/api/ai/models', { base_url: ai.base_url, api_key: ai.api_key || '' });
        modelOptions.value = r.models || [];
        if (modelOptions.value.length) {
          ElMessage.success(`获取到 ${modelOptions.value.length} 个模型，请选择`);
        } else {
          ElMessage.warning('未获取到模型');
        }
      } catch (e) { ElMessage.error(e.message); modelOptions.value = []; }
      loadingModels.value = false;
    }
    // v0.5.7: 保存配置 (profiles)
    async function saveAiProfile() {
      if (!ai.name || !ai.base_url) { ElMessage.warning('配置名和 Base URL 必填'); return; }
      try {
        await post('/api/ai/profiles', {
          name: ai.name, base_url: ai.base_url, api_key: ai.api_key,
          model: ai.model, auto_response_threshold: ai.auto_response_threshold,
          pending_review_threshold: ai.pending_review_threshold,
        });
        ElMessage.success('配置已保存');
        ai.api_key = '';
        load();
      } catch (e) { ElMessage.error(e.message); }
    }
    // v0.5.7: 激活切换
    async function activateProfile(row) {
      try {
        await post('/api/ai/activate', { name: row.name });
        ElMessage.success(`已切换到 ${row.name} (guard 3s 热加载)`);
        load();
      } catch (e) { ElMessage.error(e.message); }
    }
    async function deleteProfile(row) {
      try {
        await fetch('/api/ai/profiles/' + encodeURIComponent(row.name), { method: 'DELETE', credentials: 'same-origin' });
        ElMessage.success('配置已删除');
        load();
      } catch (e) { ElMessage.error(e.message); }
    }
    async function addUser() {
      try {
        await post('/api/members', { ...f });
        ElMessage.success('成员已创建 (首登强制改密)');
        showAdd.value = false;
        f.username = f.password = '';
        load();
      } catch (e) { ElMessage.error(e.message); }
    }
    async function changePw() {
      if (pw.new1 !== pw.new2) { ElMessage.warning('两次新密码不一致'); return; }
      try {
        await post('/api/auth/change-password', { old_password: pw.old, new_password: pw.new1 });
        ElMessage.success('密码已修改');
        pw.old = pw.new1 = pw.new2 = '';
        localStorage.setItem('guard_me', JSON.stringify({ ...me, must_change_password: false }));
      } catch (e) { ElMessage.error(e.message); }
    }
    async function issueToken() {
      try {
        // v0.5.7: for_user 独立传后端 (校验权限), note 仅用途
        const r = await post('/api/tokens/issue', {
          purpose: tokenPurpose.value, ttl: tokenTtl.value,
          for_user: tokenFor.value, note: tokenNote.value });
        issuedToken.value = r.token;
        ElMessage.success('Token 已签发 (一次性, 5 分钟内有效)');
        tokenNote.value = '';
        tokenFor.value = '';
        load();
      } catch (e) { ElMessage.error(e.message); }
    }
    onMounted(load);
    return { me, isAdmin, pw, ai, masked, profiles, modelOptions, loadingModels,
      tokenPurpose, tokenTtl, tokenFor, tokenNote, issuedToken, tokens,
      changePw, fetchModels, saveAiProfile, activateProfile, deleteProfile,
      issueToken, fmtTime, fmtTs,
      users, showAdd, f, addUser, ROLE_LABELS, ROLE_COLORS, ROLE_TYPES,
      eligibleUsers };
  },
};

/* ================================================================
 * Members
 * ================================================================ */

/* ================================================================
 * 事件详情弹窗 (v0.5.6) — 全局共用: 告警流/总览/行为日志
 * ================================================================ */
const eventDetail = reactive({ show: false, event: null, ai: null, aiPending: false });
async function openEventDetail(row) {
  eventDetail.show = true;
  eventDetail.event = null;
  eventDetail.ai = null;
  eventDetail.aiPending = false;
  // 行为日志是 syscall 原始事件 (无 rule/tier2), 直接展示
  if (!row.rule) {
    eventDetail.event = { ...row, event_type: row.event_type, event: row,
                          is_behavior: true };
    return;
  }
  try {
    const d = await get('/api/alerts/detail?ts=' + encodeURIComponent(row.timestamp));
    eventDetail.event = d.event;
    eventDetail.ai = d.ai;
    // v0.5.6: AI 异步研判中 — 事件存在但 AI 未回填 (ai_results.log
    // 无对应 event_ts 且时间接近) 时显示"AI 研判中"
    if (!d.ai && d.event && d.event.state !== 'pending_review') {
      eventDetail.aiPending = true;
    }
  } catch (e) { ElMessage.error(e.message); }
}

const EventDetailDialog = {
  template: `
  <el-dialog v-model="eventDetail.show" title="事件详情" width="640px">
    <template v-if="eventDetail.event">
      <el-descriptions :column="2" size="small" border>
        <el-descriptions-item label="规则"><span class="ev-rule">{{ eventDetail.event.rule || eventDetail.event.event_type || '—' }}</span></el-descriptions-item>
        <el-descriptions-item label="严重度">
          <el-tag v-if="eventDetail.event.severity" :type="sevTag(eventDetail.event.severity)" size="small">{{ eventDetail.event.severity }}</el-tag>
          <span v-else style="color:var(--muted)">—</span></el-descriptions-item>
        <el-descriptions-item label="容器"><span class="mono">{{ eventDetail.event.container_id }}</span></el-descriptions-item>
        <el-descriptions-item label="时间">{{ fmtTime(eventDetail.event.timestamp) }}</el-descriptions-item>
        <el-descriptions-item label="事件类型"><span class="mono">{{ eventDetail.event.event_type }}</span></el-descriptions-item>
        <el-descriptions-item label="攻击向量"><span class="mono">{{ eventDetail.event.tier2_vector || '—' }}</span></el-descriptions-item>
        <el-descriptions-item v-if="eventDetail.event.action" label="动作">{{ eventDetail.event.action }} ({{ eventDetail.event.action_status }})</el-descriptions-item>
        <el-descriptions-item v-if="eventDetail.event.state" label="状态">{{ eventDetail.event.state }}</el-descriptions-item>
        <el-descriptions-item label="进程" :span="2">
          <span class="mono">{{ eventDetail.event.event?.comm || eventDetail.event.comm || '—' }}
            (PID {{ eventDetail.event.event?.pid || eventDetail.event.pid || '?' }})</span></el-descriptions-item>
        <el-descriptions-item v-if="eventDetail.event.event?.target_path || eventDetail.event.target_path" label="目标路径" :span="2">
          <span class="mono">{{ eventDetail.event.event?.target_path || eventDetail.event.target_path }}</span></el-descriptions-item>
        <el-descriptions-item v-if="eventDetail.event.event?.daddr || eventDetail.event.daddr" label="目标地址" :span="2">
          <span class="mono">{{ eventDetail.event.event?.daddr || eventDetail.event.daddr }}:{{ eventDetail.event.event?.dport || eventDetail.event.dport || '' }}</span></el-descriptions-item>
      </el-descriptions>
      <div v-if="eventDetail.event.tier2_confidence" style="margin-top:10px;font-size:13px">
        <el-tag size="small" type="warning" style="margin-right:8px">行为矩阵</el-tag>
        置信度 <b>{{ eventDetail.event.tier2_confidence }}%</b>
        <template v-if="eventDetail.event.tier2_combo">
          <el-tag size="small" type="danger" style="margin-left:8px">组合加成</el-tag>
        </template>
      </div>
      <div v-if="eventDetail.event.tier2_narrative" style="margin-top:6px;font-size:13px;color:var(--muted)">
        行为矩阵: {{ eventDetail.event.tier2_narrative }}</div>
    </template>

    <div v-if="eventDetail.aiPending" style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px">
      <h4 style="margin-bottom:8px">🤖 AI 研判 <el-tag type="info" size="small" style="margin-left:8px">研判中…</el-tag></h4>
      <p style="font-size:13px;color:var(--muted)">AI 异步研判进行中 (DeepSeek 分析约需数秒), 稍后刷新可见结果。</p>
    </div>
    <div v-else-if="eventDetail.ai" style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px">
      <h4 style="margin-bottom:8px">🤖 AI 研判
        <el-tag :type="eventDetail.ai.ai_verdict === 'true_positive' ? 'danger' : 'success'" size="small" style="margin-left:8px">
          {{ eventDetail.ai.ai_verdict === 'true_positive' ? '真实攻击' : '误报' }} {{ eventDetail.ai.ai_confidence }}%</el-tag>
      </h4>
      <p style="font-size:13px;line-height:1.7;margin-bottom:8px">{{ eventDetail.ai.ai_report }}</p>
      <p v-if="eventDetail.ai.ai_technique" style="font-size:12px;color:var(--muted)">手法: {{ eventDetail.ai.ai_technique }}</p>
    </div>
    <div v-else-if="eventDetail.event && eventDetail.event.is_behavior"
         style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px">
      <p style="font-size:13px;color:var(--muted)">行为日志为原始 syscall 事件, 不触发 AI 研判。</p>
    </div>
    <div v-else-if="eventDetail.event" style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px">
      <p style="font-size:13px;color:var(--muted)">该事件未触发 AI 研判 (矩阵置信度不在 60-85 区间或 AI 未配置)</p>
    </div>
    <template #footer>
      <el-button v-if="eventDetail.event && eventDetail.event.container_id"
                 type="primary" @click="viewChain">🔗 查看攻击链</el-button>
    </template>
  </el-dialog>`,
  setup() {
    // v0.5.8: 跳转攻击链页面
    function viewChain() {
      const cid = eventDetail.event.container_id;
      const ts = eventDetail.event.timestamp;
      eventDetail.show = false;  // 跳转攻击链自动关弹窗
      location.hash = '#/chain?container=' + encodeURIComponent(cid) +
                      '&ts=' + encodeURIComponent(ts);
    }
    return { eventDetail, sevTag, fmtTime, viewChain };
  },
};

/* ================================================================
 * 布局 + 哈希路由
 * ================================================================ */
const pages = {
  overview: { title: '总览', icon: '📊', comp: OverviewPage, roles: ['admin', 'operator', 'analyst'] },
  assets: { title: '资产管理', icon: '🗄️', comp: AssetsPage, roles: ['admin', 'operator', 'analyst'] },
  alerts: { title: '告警流', icon: '🚨', comp: AlertsPage, roles: ['admin', 'operator', 'analyst'] },
  review: { title: '人工确认队列', icon: '🧐', comp: ReviewPage, roles: ['admin', 'operator'] },
  behavior: { title: '行为日志', icon: '📜', comp: BehaviorPage, roles: ['admin', 'operator', 'analyst'] },
  rules: { title: '检测规则', icon: '📋', comp: RulesPage, roles: ['admin', 'operator', 'analyst'] },
  ai_rules: { title: 'AI 建议规则', icon: '🤖', comp: AiRulesPage, roles: ['admin', 'operator', 'analyst'] },
  settings: { title: '设置', icon: '⚙️', comp: SettingsPage, roles: ['admin', 'operator', 'analyst'] },
  chain: { title: '攻击链', icon: '🔗', comp: AttackChainPage, roles: ['admin', 'operator', 'analyst'], hidden: true },
};

/* ================================================================
 * 主题 (v0.5.6): 暗/亮/跟随系统 — CSS 变量切换 + EP dark css 联动
 * ================================================================ */
const THEME_KEY = 'guard_theme';
function applyTheme(mode) {
  const dark = mode === 'dark' ||
    (mode === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.classList.toggle('dark', dark);   // EP dark css
  document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
}
const themeState = reactive({ mode: localStorage.getItem(THEME_KEY) || 'system' });
function setTheme(mode) {
  themeState.mode = mode;
  localStorage.setItem(THEME_KEY, mode);
  applyTheme(mode);
}
// 跟随系统: 系统主题变化时实时切换
const mq = window.matchMedia('(prefers-color-scheme: dark)');
mq.addEventListener('change', () => {
  if (themeState.mode === 'system') applyTheme('system');
});
applyTheme(themeState.mode);

const App = {
  template: `
  <div v-if="!authed" style="min-height:100vh"><login-page :on-logged-in="onLoggedIn" /></div>
  <div v-else class="layout">
    <header class="topbar">
      <div class="topbar-left">
        <button class="logout collapse-btn" @click="toggleSidebar" title="收起/展开导航">≪</button>
        <h2>🛡️ Container Guard</h2>
        <span class="topbar-sub">eBPF 容器逃逸检测与防护</span>
      </div>
      <div class="topbar-right">
        <el-select v-model="themeState.mode" size="small" style="width:96px"
                   @change="setTheme" title="主题">
          <el-option label="🌙 暗色" value="dark" />
          <el-option label="☀️ 亮色" value="light" />
          <el-option label="🖥️ 跟随系统" value="system" />
        </el-select>
        <span class="topbar-user">{{ me.username }}
          <el-tag size="small" :type="ROLE_TYPES[me.role] || 'info'"
                  :color="ROLE_COLORS[me.role] || ''"
                  :style="ROLE_COLORS[me.role] ? 'color:#fff;border:none' : ''"
                  style="margin-left:6px">{{ ROLE_LABELS[me.role] || me.role }}</el-tag>
        </span>
        <button class="logout" @click="logout">退出</button>
      </div>
    </header>
    <aside class="sidebar" :class="{ collapsed: sidebarCollapsed }">
      <nav class="nav">
        <a v-for="(p, key) in allowedPages" :key="key"
           :class="{ active: route === key && !mustChangePw }" @click="go(key)"
           :title="p.title">
          <span class="nav-icon">{{ p.icon }}</span>
          <span v-if="!sidebarCollapsed" class="nav-label">{{ p.title }}</span>
        </a>
      </nav>
      <!-- v0.5.7: AI 快捷配置 (左下角) -->
      <div v-if="!sidebarCollapsed" class="ai-quick">
        <div class="ai-quick-title">🤖 AI 快捷配置</div>
        <el-select v-model="aiQuick.name" placeholder="选择配置" size="small"
                   style="width:100%" @change="loadAiQuickThresholds">
          <el-option v-for="p in aiProfiles" :key="p.name"
                     :label="p.name + (p.active ? ' (当前)' : '')" :value="p.name" />
        </el-select>
        <div class="ai-quick-row">
          <span>响应阈值</span>
          <el-input-number v-model="aiQuick.auto_response_threshold" :min="0" :max="100"
                           size="small" style="width:90px" />
        </div>
        <div class="ai-quick-row">
          <span>审核阈值</span>
          <el-input-number v-model="aiQuick.pending_review_threshold" :min="0" :max="100"
                           size="small" style="width:90px" />
        </div>
        <el-button type="primary" size="small" style="width:100%;margin-top:8px"
                   :loading="aiQuickSaving" @click="aiQuickSave">确认切换</el-button>
        <a class="ai-quick-link" @click="go('settings')">→ 详细配置</a>
      </div>
    </aside>
    <main class="main">
      <div v-if="mustChangePw" class="panel" style="max-width:480px;margin:60px auto">
        <h3>🔒 首次登录请修改密码</h3>
        <p style="color:var(--muted);font-size:13px;margin:8px 0 16px">
          账号 {{ me.username }} 使用初始密码, 修改后才能使用面板。</p>
        <el-form :model="pw" label-width="80px" size="small" @submit.prevent>
          <el-form-item label="旧密码"><el-input v-model="pw.old" type="password" show-password /></el-form-item>
          <el-form-item label="新密码"><el-input v-model="pw.new1" type="password" show-password /></el-form-item>
          <el-form-item label="确认新密码"><el-input v-model="pw.new2" type="password" show-password /></el-form-item>
          <el-button type="primary" :loading="savingPw" @click="submitMustChange">修改并进入</el-button>
        </el-form>
      </div>
      <component v-else :is="currentComp" />
    </main>
    <event-detail-dialog />
  </div>`,
  components: { 'login-page': LoginPage, 'event-detail-dialog': EventDetailDialog },
  setup() {
    const authed = ref(false);
    const me = reactive({ username: '', role: '', must_change_password: false });
    const route = ref('overview');
    const allowedPages = ref(Object.fromEntries(
      Object.entries(pages).filter(([, p]) => !p.hidden)));
    const sidebarCollapsed = ref(localStorage.getItem('guard_sidebar') === '1');
    // v0.5.7: AI 快捷配置 (左下角)
    const aiProfiles = ref([]);
    const aiQuick = reactive({ name: '', auto_response_threshold: 85, pending_review_threshold: 60 });
    const aiQuickSaving = ref(false);
    async function loadAiQuick() {
      try {
        const prof = await get('/api/ai/profiles');
        aiProfiles.value = prof.profiles || [];
        const active = prof.profiles?.find(p => p.active) || prof.profiles?.[0];
        if (active) {
          aiQuick.name = active.name;
          aiQuick.auto_response_threshold = active.auto_response_threshold ?? 85;
          aiQuick.pending_review_threshold = active.pending_review_threshold ?? 60;
        }
      } catch (e) {}
    }
    function loadAiQuickThresholds() {
      const p = aiProfiles.value.find(x => x.name === aiQuick.name);
      if (p) {
        aiQuick.auto_response_threshold = p.auto_response_threshold ?? 85;
        aiQuick.pending_review_threshold = p.pending_review_threshold ?? 60;
      }
    }
    async function aiQuickSave() {
      if (!aiQuick.name) { ElMessage.warning('先选择配置'); return; }
      aiQuickSaving.value = true;
      try {
        await post('/api/ai/activate', {
          name: aiQuick.name,
          thresholds: {
            auto_response_threshold: aiQuick.auto_response_threshold,
            pending_review_threshold: aiQuick.pending_review_threshold,
          },
        });
        ElMessage.success(`已切换到 ${aiQuick.name} (阈值已保存)`);
        loadAiQuick();
      } catch (e) { ElMessage.error(e.message); }
      aiQuickSaving.value = false;
    }
    function toggleSidebar() {
      sidebarCollapsed.value = !sidebarCollapsed.value;
      localStorage.setItem('guard_sidebar', sidebarCollapsed.value ? '1' : '0');
    }
    // 收起时切页自动展开 (避免图标导航盲点)
    function go(key) {
      location.hash = '#' + key;
      if (sidebarCollapsed.value) { sidebarCollapsed.value = false; localStorage.setItem('guard_sidebar', '0'); }
    }

    async function refreshMe() {
      try {
        const r = await get('/api/auth/me');
        if (r.authenticated) {
          authed.value = true;
          Object.assign(me, r);
          localStorage.setItem('guard_me', JSON.stringify(r));
          mustChangePw.value = !!r.must_change_password;
        } else {
          authed.value = false;
          location.hash = '#/login';
        }
      } catch (e) { authed.value = false; }
    }
    // 强制改密 (v0.5.6): 初始账号首登必须改密, 否则一直停留在改密视图
    const mustChangePw = ref(false);
    const pw = reactive({ old: '', new1: '', new2: '' });
    const savingPw = ref(false);
    async function submitMustChange() {
      if (pw.new1 !== pw.new2) { ElMessage.warning('两次新密码不一致'); return; }
      savingPw.value = true;
      try {
        await post('/api/auth/change-password', { old_password: pw.old, new_password: pw.new1 });
        ElMessage.success('密码已修改');
        mustChangePw.value = false;
        me.must_change_password = false;
        localStorage.setItem('guard_me', JSON.stringify({ ...me, must_change_password: false }));
        pw.old = pw.new1 = pw.new2 = '';
        location.hash = '#/overview';
      } catch (e) { ElMessage.error(e.message); }
      savingPw.value = false;
    }
    function onHash() {
      // 兼容 #/alerts 与 #alerts 两种格式: 去 # 和 前导斜杠, 剥 ?filter=
      const raw = location.hash.replace('#', '').replace(/^\//, '') || 'overview';
      const key = raw.split('?')[0];
      route.value = pages[key] ? key : 'overview';
    }
    async function logout() {
      try { await post('/api/auth/logout'); } catch (e) {}
      localStorage.removeItem('guard_me');
      authed.value = false;
      location.hash = '#/login';
    }
    // 登录成功后立即刷新认证状态 (authed → true → 主界面渲染, 无需强制刷新)
    // 登录成功后立即刷新认证状态 + 加载 AI 配置 (authed 前 API 会 401)
    const onLoggedIn = () => { refreshMe(); loadAiQuick(); };

    const currentComp = computed(() => pages[route.value]?.comp || OverviewPage);

    onMounted(() => {
      onHash();
      window.addEventListener('hashchange', onHash);
      refreshMe();
      loadAiQuick();
    });
    return { authed, me, route, allowedPages, currentComp, go, logout, onLoggedIn,
             themeState, setTheme, sidebarCollapsed, toggleSidebar,
             ROLE_LABELS, ROLE_COLORS, ROLE_TYPES,
             mustChangePw, pw, savingPw, submitMustChange,
             aiProfiles, aiQuick, aiQuickSaving, loadAiQuickThresholds, aiQuickSave };
  },
};

createApp(App).use(ElementPlus).mount('#app');
