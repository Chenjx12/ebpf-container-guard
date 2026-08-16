/* eBPF Container Guard — 安全面板 SPA (v0.5.6)
 * Vue3 + Element Plus CDN, 零构建, 哈希路由。
 * 页面: overview / alerts / review_queue / behavior_log / rules / ai_rules / settings / members
 */
const { createApp, ref, reactive, computed, onMounted, onUnmounted } = Vue;
const ElMessage = ElementPlus.ElMessage;

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
      <el-table :data="s.recent_events" size="small" stripe>
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
    function goPage(key) { location.hash = '#' + key; }
    usePolling(load, 3000);
    return { s, fmtTime, sevTag, goAlerts, goPage };
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
                @row-click="showDetail">
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

    <el-dialog v-model="detail.show" title="事件详情" width="640px">
      <template v-if="detail.event">
        <el-descriptions :column="2" size="small" border>
          <el-descriptions-item label="规则"><span class="ev-rule">{{ detail.event.rule }}</span></el-descriptions-item>
          <el-descriptions-item label="严重度">
            <el-tag :type="sevTag(detail.event.severity)" size="small">{{ detail.event.severity }}</el-tag></el-descriptions-item>
          <el-descriptions-item label="容器"><span class="mono">{{ detail.event.container_id }}</span></el-descriptions-item>
          <el-descriptions-item label="时间">{{ fmtTime(detail.event.timestamp) }}</el-descriptions-item>
          <el-descriptions-item label="事件类型"><span class="mono">{{ detail.event.event_type }}</span></el-descriptions-item>
          <el-descriptions-item label="攻击向量"><span class="mono">{{ detail.event.tier2_vector || '—' }}</span></el-descriptions-item>
          <el-descriptions-item label="动作">{{ detail.event.action }} ({{ detail.event.action_status }})</el-descriptions-item>
          <el-descriptions-item label="状态">{{ detail.event.state }}</el-descriptions-item>
          <el-descriptions-item label="进程" :span="2">
            <span class="mono">{{ detail.event.event?.comm || '—' }} (PID {{ detail.event.event?.pid || '?' }})</span></el-descriptions-item>
          <el-descriptions-item v-if="detail.event.event?.target_path" label="目标路径" :span="2">
            <span class="mono">{{ detail.event.event.target_path }}</span></el-descriptions-item>
          <el-descriptions-item v-if="detail.event.event?.daddr" label="目标地址" :span="2">
            <span class="mono">{{ detail.event.event.daddr }}:{{ detail.event.event.dport }}</span></el-descriptions-item>
        </el-descriptions>
        <div v-if="detail.event.tier2_narrative" style="margin-top:10px;font-size:13px;color:var(--muted)">
          行为矩阵: {{ detail.event.tier2_narrative }}</div>
      </template>

      <div v-if="detail.ai" style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px">
        <h4 style="margin-bottom:8px">🤖 AI 研判
          <el-tag :type="detail.ai.ai_verdict === 'true_positive' ? 'danger' : 'success'" size="small" style="margin-left:8px">
            {{ detail.ai.ai_verdict === 'true_positive' ? '真实攻击' : '误报' }} {{ detail.ai.ai_confidence }}%</el-tag>
        </h4>
        <p style="font-size:13px;line-height:1.7;margin-bottom:8px">{{ detail.ai.ai_report }}</p>
        <p v-if="detail.ai.ai_technique" style="font-size:12px;color:var(--muted)">手法: {{ detail.ai.ai_technique }}</p>
      </div>
      <div v-else-if="detail.event" style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px">
        <p style="font-size:13px;color:var(--muted)">该事件未触发 AI 研判 (矩阵置信度不在 60-85 区间或 AI 未配置)</p>
      </div>
    </el-dialog>
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
    // 事件详情弹窗 (v0.5.6): 点击行 → 详情 + 关联 AI 研判
    const detail = reactive({ show: false, event: null, ai: null });
    async function showDetail(row) {
      detail.show = true;
      detail.event = null; detail.ai = null;
      try {
        const d = await get('/api/alerts/detail?ts=' + encodeURIComponent(row.timestamp));
        detail.event = d.event; detail.ai = d.ai;
      } catch (e) { ElMessage.error(e.message); }
    }
    onMounted(() => { readHash(); state.timer = setInterval(load, 3000); });
    onUnmounted(() => clearInterval(state.timer));
    window.addEventListener('hashchange', readHash);
    return { events, curFilter, filterLabel, clearFilter, resetFilter, q, ruleOptions,
             detail, showDetail, fmtTime, sevTag };
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
      <el-table :data="events" size="small" max-height="68vh">
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
    return { q, events, load, fmtTime };
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

    <div class="panel"><h3>AI 研判配置 <span class="sub">guard 3s 热加载</span></h3>
      <el-form :model="ai" label-width="120px" size="small" style="max-width:560px">
        <el-form-item label="模型"><el-input v-model="ai.model" placeholder="deepseek-chat" /></el-form-item>
        <el-form-item label="Base URL"><el-input v-model="ai.base_url" placeholder="https://api.deepseek.com/v1" /></el-form-item>
        <el-form-item label="API Key"><el-input v-model="ai.api_key" type="password" show-password
          :placeholder="masked || '留空保持现有'" /></el-form-item>
        <el-form-item label="自动响应阈值"><el-input-number v-model="ai.auto_response_threshold" :min="0" :max="100" /></el-form-item>
        <el-form-item label="待审阈值"><el-input-number v-model="ai.pending_review_threshold" :min="0" :max="100" /></el-form-item>
        <el-button type="primary" size="small" @click="saveAi">保存 (3s 热加载)</el-button>
      </el-form>
    </div>

    <div v-if="isAdmin" class="panel"><h3>临时授权 Token</h3>
      <div style="display:flex;gap:10px;align-items:center;margin-bottom:12px;flex-wrap:wrap">
        <el-select v-model="tokenPurpose" style="width:150px" size="small">
          <el-option label="add_member" value="add_member" />
          <el-option label="add_rule" value="add_rule" />
        </el-select>
        <el-input-number v-model="tokenTtl" :min="60" :max="300" :step="30" size="small" />
        <el-input v-model="tokenNote" placeholder="备注 (给谁/为什么)" size="small" style="width:220px" clearable />
        <el-button type="primary" size="small" @click="issueToken">签发</el-button>
        <el-input v-model="issuedToken" readonly size="small" style="width:240px" placeholder="签发后显示" />
      </div>
      <el-table :data="tokens" size="small">
        <el-table-column prop="token" label="Token (前 8 位)" width="130" />
        <el-table-column prop="purpose" label="用途" width="110" />
        <el-table-column prop="grantor" label="签发人" width="100" />
        <el-table-column prop="note" label="备注" min-width="140">
          <template #default="{row}">{{ row.note || '—' }}</template>
        </el-table-column>
        <el-table-column label="过期" width="200"><template #default="{row}">{{ fmtTs(row.expires) }}</template></el-table-column>
      </el-table>
    </div>
  </div>`,
  setup() {
    const me = JSON.parse(localStorage.getItem('guard_me') || '{}');
    const isAdmin = computed(() => me.role === 'admin');
    const pw = reactive({ old: '', new1: '', new2: '' });
    const ai = reactive({ model: '', base_url: '', api_key: '', auto_response_threshold: 85, pending_review_threshold: 60 });
    const masked = ref('');
    const tokenPurpose = ref('add_member');
    const tokenTtl = ref(180);
    const tokenNote = ref('');
    const issuedToken = ref('');
    const tokens = ref([]);

    async function load() {
      try {
        const cfg = await get('/api/config/ai');
        ai.model = cfg.model || 'deepseek-chat';
        ai.base_url = cfg.base_url || 'https://api.deepseek.com/v1';
        masked.value = cfg.api_key_masked || '';
        if (cfg.auto_response_threshold) ai.auto_response_threshold = cfg.auto_response_threshold;
        if (cfg.pending_review_threshold) ai.pending_review_threshold = cfg.pending_review_threshold;
      } catch (e) {}
      if (isAdmin.value) { try { tokens.value = (await get('/api/tokens/list')).tokens; } catch (e) {} }
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
    async function saveAi() {
      try {
        const body = { model: ai.model, base_url: ai.base_url,
          auto_response_threshold: ai.auto_response_threshold,
          pending_review_threshold: ai.pending_review_threshold };
        if (ai.api_key) body.api_key = ai.api_key;
        await put('/api/config/ai', body);
        ElMessage.success('AI 配置已保存 (3s 热加载)');
        ai.api_key = '';
        load();
      } catch (e) { ElMessage.error(e.message); }
    }
    async function issueToken() {
      try {
        const r = await post('/api/tokens/issue', { purpose: tokenPurpose.value, ttl: tokenTtl.value, note: tokenNote.value });
        issuedToken.value = r.token;
        ElMessage.success('Token 已签发 (一次性, 5 分钟内有效)');
        tokenNote.value = '';
        load();
      } catch (e) { ElMessage.error(e.message); }
    }
    onMounted(load);
    return { me, isAdmin, pw, ai, masked, tokenPurpose, tokenTtl, tokenNote, issuedToken, tokens,
      changePw, saveAi, issueToken, fmtTime, fmtTs };
  },
};

/* ================================================================
 * Members
 * ================================================================ */
const MembersPage = {
  template: `
  <div>
    <div class="page-title">成员管理 <span class="sub">config/users.yaml</span></div>
    <div class="panel" style="display:flex;justify-content:space-between;align-items:center">
      <span style="color:var(--muted)">共 {{ users.length }} 个账号</span>
      <el-button type="primary" size="small" @click="showAdd = true">添加成员</el-button>
    </div>
    <div class="panel">
      <el-table :data="users" size="small" stripe>
        <el-table-column prop="username" label="用户名" min-width="160" />
        <el-table-column label="角色" width="120"><template #default="{row}">
          <el-tag size="small" :type="row.role === 'admin' ? 'danger' : row.role === 'operator' ? 'warning' : 'info'">
            {{ row.role }}</el-tag></template></el-table-column>
        <el-table-column prop="created" label="创建时间" width="200" />
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
    const users = ref([]);
    const showAdd = ref(false);
    const f = reactive({ username: '', password: '', role: 'analyst' });
    async function load() {
      try { users.value = (await get('/api/members')).users; } catch (e) {}
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
    onMounted(load);
    return { users, showAdd, f, addUser };
  },
};

/* ================================================================
 * 布局 + 哈希路由
 * ================================================================ */
const pages = {
  overview: { title: '总览', comp: OverviewPage, roles: ['admin', 'operator', 'analyst'] },
  alerts: { title: '告警流', comp: AlertsPage, roles: ['admin', 'operator', 'analyst'] },
  review: { title: '人工确认队列', comp: ReviewPage, roles: ['admin', 'operator'] },
  behavior: { title: '行为日志', comp: BehaviorPage, roles: ['admin', 'operator', 'analyst'] },
  rules: { title: '检测规则', comp: RulesPage, roles: ['admin', 'operator', 'analyst'] },
  ai_rules: { title: 'AI 建议规则', comp: AiRulesPage, roles: ['admin', 'operator', 'analyst'] },
  settings: { title: '设置', comp: SettingsPage, roles: ['admin', 'operator', 'analyst'] },
  members: { title: '成员管理', comp: MembersPage, roles: ['admin'] },
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
           :title="p.title">{{ sidebarCollapsed ? p.title[0] : p.title }}</a>
      </nav>
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
  </div>`,
  components: { 'login-page': LoginPage },
  setup() {
    const authed = ref(false);
    const me = reactive({ username: '', role: '', must_change_password: false });
    const route = ref('overview');
    const allowedPages = ref(pages);
    const sidebarCollapsed = ref(localStorage.getItem('guard_sidebar') === '1');
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
    const onLoggedIn = () => refreshMe();

    const currentComp = computed(() => pages[route.value]?.comp || OverviewPage);

    onMounted(() => {
      onHash();
      window.addEventListener('hashchange', onHash);
      refreshMe();
    });
    return { authed, me, route, allowedPages, currentComp, go, logout, onLoggedIn,
             themeState, setTheme, sidebarCollapsed, toggleSidebar,
             ROLE_LABELS, ROLE_COLORS, ROLE_TYPES,
             mustChangePw, pw, savingPw, submitMustChange };
  },
};

createApp(App).use(ElementPlus).mount('#app');
