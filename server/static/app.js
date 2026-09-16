/* eBPF Container Guard — 安全面板 SPA (v0.5.6)
 * Vue3 + Element Plus CDN, 零构建, 哈希路由。
 * 页面: overview / alerts / review_queue / behavior_log / rules / ai_rules / settings / members
 */
const { createApp, ref, reactive, computed, onMounted, onUnmounted } = Vue;
const ElMessage = ElementPlus.ElMessage;
const ElMessageBox = ElementPlus.ElMessageBox;
const ElNotification = ElementPlus.ElNotification;

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
// 资产存活时长 (人类可读): 便于一眼区分「刚起的新容器」与长期运行资产。
//   Docker 与 k8s 都给 UTC 时间戳; 缺时区后缀时补 'Z' 按 UTC 解析 (与后端一致)
const assetAge = (created) => {
  if (!created) return '';
  const s0 = String(created).replace(' ', 'T');
  const t = Date.parse(/[Zz]$|[+-]\d{2}:\d{2}$/.test(s0) ? s0 : s0 + 'Z');
  if (!t || Number.isNaN(t)) return '';
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 60) return s + ' 秒';
  const m = Math.floor(s / 60); if (m < 60) return m + ' 分钟';
  const h = Math.floor(m / 60); if (h < 24) return h + ' 小时';
  const d = Math.floor(h / 24);
  return d + ' 天' + (h % 24 ? ' ' + (h % 24) + ' 小时' : '');
};
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
 * 资产状态机常量 (v0.6.4, ADR-050) — 与后端 src/core/assets.py 对齐
 * asset_state: PENDING_REVIEW / CONFIRMED / OVERRIDDEN
 * level: critical / high / medium / low, level_source: auto / override
 * ================================================================ */
const ASSET_STATES = { PENDING_REVIEW: '待确认', CONFIRMED: '已确认', OVERRIDDEN: '已覆盖' };
const ASSET_STATE_TYPES = { PENDING_REVIEW: 'warning', CONFIRMED: 'success', OVERRIDDEN: 'primary' };
const LEVEL_TYPES = { critical: 'danger', high: 'warning', medium: 'primary', low: 'info' };
// 资产分级 = 业务重要性, 不是漏洞危害等级 — 后者是 严重/高危/中危/低危 (CVSS),
// 两者语义不同: 一个"边缘"资产同样可能跑着严重漏洞的服务。
// 数据值仍为 critical/high/medium/low (与后端 config/assets.yaml + 存量
// logs/assets.yaml 兼容), 此处只改展示文案。
const LEVEL_LABELS = { critical: '核心', high: '重要', medium: '一般', low: '边缘' };
const ASSET_LEVEL_OPTIONS = ['critical', 'high', 'medium', 'low'];
// 多选并列筛选谓词: 选中集合为空 = 不限制; 否则命中任一即可 (OR 语义)。
// 放在顶层是因为 buildTopo() 与 matchAsset() (列表) 都要用同一套判定,
// 若各写一份或只在 buildTopo 内定义, 拓扑与清单的筛选结果会不一致。
const inSet = (sel, val) => !sel || !sel.length || sel.indexOf(val) !== -1;
// docker 容器的伪命名空间: 它没有 k8s namespace, 但需要一个可筛选的归属维度。
// 放在命名空间下拉里统一呈现, 而不是单独加"显示本地容器"开关 —
// docker 容器只能来自被监控的这台机器, 不存在"其他机器的 docker"。
const DOCKER_NS = 'docker';
// v0.6.4: docker 模式容器在拓扑中的分组名 (无 node/namespace 维度)
const DOCKER_GROUP = '本地 docker';

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
    onMounted(() => {
      readHash();
      window.addEventListener('hashchange', readHash);  // v0.6.4 M1: 随组件卸载配对移除
      state.timer = setInterval(load, 3000);
    });
    onUnmounted(() => {
      window.removeEventListener('hashchange', readHash);
      clearInterval(state.timer);
    });
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
    <!-- v0.6.4 批量工具栏 -->
    <div class="panel" style="display:flex;align-items:center;gap:12px;padding:10px 18px;margin-bottom:14px">
      <el-checkbox :model-value="allSelected" @change="toggleSelectAll">全选</el-checkbox>
      <span style="font-size:13px;color:var(--muted)">已选 <b style="color:var(--accent)">{{ selectedIds.length }}</b> 组</span>
      <div style="margin-left:auto;display:flex;gap:8px">
        <el-button type="danger" size="small" :disabled="!selectedIds.length" @click="batchDecide('confirmed')">批量确认攻击</el-button>
        <el-button type="warning" size="small" :disabled="!selectedIds.length" @click="openBatchIgnore">批量忽略</el-button>
      </div>
    </div>

    <div v-if="groups.length === 0" class="panel" style="color:var(--muted)">暂无待判决事件 🎉</div>
    <el-collapse v-model="openNames" style="margin-bottom:18px" @change="onExpand">
      <el-collapse-item v-for="g in groups" :key="g.container_id" :name="g.container_id">
        <template #title>
          <div style="display:flex;align-items:center;gap:12px;flex:1;min-width:0">
            <el-checkbox :model-value="isSelected(g.container_id)" @click.stop="toggleSelect(g, $event)" />
            <span class="mono" style="font-weight:600">{{ g.container_id }}</span>
            <el-tag size="small" :type="g.event_count > 10 ? 'danger' : 'warning'">{{ g.event_count }} 事件</el-tag>
            <el-tag v-if="g.profile" size="small" type="info" style="max-width:300px;overflow:hidden;text-overflow:ellipsis">
              {{ g.profile.image }} · {{ g.profile.status }}
              <template v-if="g.profile.privileged"> · 特权</template>
            </el-tag>
            <span style="font-size:12px;color:var(--muted)">点击展开明细</span>
          </div>
          <div style="display:flex;align-items:center;gap:8px;margin-right:12px">
            <el-button type="danger" size="small" @click.stop="openConfirm(g)">确认攻击</el-button>
            <el-button type="warning" size="small" @click.stop="openIgnore(g)">忽略</el-button>
          </div>
        </template>
        <div style="padding:0 4px">
          <el-descriptions v-if="g.profile" :column="3" size="small" border style="margin-bottom:10px">
            <el-descriptions-item label="镜像">{{ g.profile.image }}
              <el-tag size="small" :type="g.profile.runtime === 'k8s' ? 'primary' : 'success'"
                      style="margin-left:6px">{{ g.profile.runtime === 'k8s' ? 'k8s' : 'docker' }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="状态">{{ g.profile.status }}</el-descriptions-item>
            <el-descriptions-item label="特权">
            <el-tag size="small" :type="g.profile.privileged ? 'danger' : 'primary'">{{ g.profile.privileged ? '是' : '否' }}</el-tag></el-descriptions-item>
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

    <!-- 确认攻击二次弹窗 -->
    <el-dialog v-model="confirmDlg.show" :title="confirmDlg.title" width="520px">
      <div v-if="confirmDlg.g" style="line-height:1.9">
        <p style="margin-bottom:10px">该容器命中 <b>{{ confirmDlg.g.event_count }}</b> 条攻击事件，确认后将</p>
        <p style="margin-bottom:8px">
          <el-tag type="danger" size="small" style="margin-right:6px" v-for="(r,c) in confirmDlg.rules" :key="c">{{ r }}</el-tag>
        </p>
        <p style="color:var(--muted);font-size:13px">确认攻击 → 触发响应（冻结/网络阻断）。此操作不可逆（可后续驳回解除）。</p>
      </div>
      <template #footer>
        <el-button size="small" @click="confirmDlg.show=false">取消</el-button>
        <el-button type="danger" size="small" @click="doConfirm">确认攻击并触发响应</el-button>
      </template>
    </el-dialog>

    <!-- 忽略弹窗 -->
    <el-dialog v-model="ignoreDlg.show" :title="ignoreDlg.title" width="600px">
      <div v-if="ignoreDlg.ids.length">
        <p style="margin-bottom:12px;color:var(--muted)">已选 <b style="color:var(--accent)">{{ ignoreDlg.ids.length }}</b> 组（{{ ignoreDlg.events }} 条事件）</p>

        <!-- 原因类别 -->
        <el-form label-width="120px" label-position="right">
          <el-form-item label="原因类别">
            <el-radio-group v-model="ignoreDlg.decision">
              <el-radio label="dismissed">误报 / 驳回</el-radio>
              <el-radio label="ignored">放行 / 其他原因（测试、业务需要）</el-radio>
            </el-radio-group>
          </el-form-item>
          <el-form-item :label="ignoreDlg.decision === 'dismissed' ? '为什么是误报' : '放行理由'">
            <el-input v-model="ignoreDlg.reason" type="textarea" :rows="2"
                      placeholder="必填 — 留痕供 AI 基线学习与审计" />
          </el-form-item>
          <el-form-item label="加入白名单">
            <el-switch v-model="ignoreDlg.whitelist" />
            <span style="font-size:12px;color:var(--muted);margin-left:8px">
              {{ ignoreDlg.whitelist ? '有效期内抑制同类告警（可管理/续期）' : '关闭：仅本次放行' }}</span>
          </el-form-item>
          <template v-if="ignoreDlg.whitelist">
            <el-form-item label="白名单粒度">
              <el-radio-group v-model="ignoreDlg.wlKind">
                <el-radio label="comm">按进程 comm</el-radio>
                <el-radio label="container">按容器</el-radio>
              </el-radio-group>
            </el-form-item>
            <el-form-item label="匹配值">
              <el-input v-model="ignoreDlg.wlMatch" placeholder="如 coredns / 容器 ID" style="width:260px" />
            </el-form-item>
            <el-form-item label="有效时限">
              <el-radio-group v-model="ignoreDlg.wlDuration">
                <el-radio label="1h">1 小时</el-radio>
                <el-radio label="24h">24 小时</el-radio>
                <el-radio label="7d">7 天</el-radio>
                <el-radio label="永久">永久</el-radio>
                <el-radio label="custom">自定义</el-radio>
              </el-radio-group>
              <el-date-picker v-if="ignoreDlg.wlDuration === 'custom'" v-model="ignoreDlg.wlUntil"
                type="datetime" placeholder="选择过期时间" value-format="YYYY-MM-DDTHH:mm:ss"
                style="margin-top:8px" />
            </el-form-item>
          </template>
        </el-form>
      </div>
      <template #footer>
        <el-button size="small" @click="ignoreDlg.show=false">取消</el-button>
        <el-button type="warning" size="small" :disabled="!ignoreDlg.reason" @click="doIgnore">确认忽略</el-button>
      </template>
    </el-dialog>
  </div>`,
  setup() {
    const groups = ref([]);
    const openNames = ref([]);  // 默认全部收起, 点击展开
    const selectedIds = ref([]);  // v0.6.4 批量多选
    const confirmDlg = reactive({ show: false, g: null, title: '', rules: [] });
    const ignoreDlg = reactive({
      show: false, ids: [], events: 0, decision: 'dismissed',
      reason: '', whitelist: false, wlKind: 'comm', wlMatch: '',
      wlDuration: '24h', wlUntil: '',
    });

    async function load() {
      try {
        const raw = (await get('/api/review/queue')).groups || [];
        // v0.6.0: 保留已展开的画像 (轮询覆盖不掉)
        const oldMap = {};
        for (const g of groups.value) if (g.profile) oldMap[g.container_id] = g.profile;
        for (const g of raw) if (oldMap[g.container_id]) g.profile = oldMap[g.container_id];
        groups.value = raw;
      } catch (e) {}
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

    // ---- 批量多选 ----
    function isSelected(cid) { return selectedIds.value.includes(cid); }
    function toggleSelect(g, ev) {
      ev && ev.stopPropagation && ev.stopPropagation();
      const i = selectedIds.value.indexOf(g.container_id);
      if (i >= 0) selectedIds.value.splice(i, 1);
      else selectedIds.value.push(g.container_id);
    }
    const allSelected = computed(() =>
      groups.value.length > 0 &&
      selectedIds.value.length === groups.value.length);
    function toggleSelectAll(v) {
      selectedIds.value = v ? groups.value.map(g => g.container_id) : [];
    }

    // ---- 确认攻击二次弹窗 ----
    function openConfirm(g) {
      const ruleCount = {};
      for (const ev of g.events || []) ruleCount[ev.rule] = (ruleCount[ev.rule] || 0) + 1;
      confirmDlg.rules = Object.entries(ruleCount).slice(0, 4)
        .map(([k, v]) => `${k} ×${v}`);
      confirmDlg.g = g;
      confirmDlg.title = `确认攻击 · ${g.container_id}`;
      confirmDlg.show = true;
    }
    async function doConfirm() {
      const g = confirmDlg.g;
      try {
        await post('/api/review/decision', { container_id: g.container_id, decision: 'confirmed', event_count: g.event_count });
        ElMessage.success('已确认攻击 → 冻结执行中');
        dropSelected(g.container_id);
        confirmDlg.show = false;
        load();
      } catch (e) { ElMessage.error(e.message); }
    }

    // ---- 忽略弹窗 ----
    function openIgnore(g) {
      ignoreDlg.ids = [g.container_id];
      ignoreDlg.events = g.event_count;
      ignoreDlg.decision = 'dismissed';
      ignoreDlg.reason = '';
      ignoreDlg.whitelist = false;
      ignoreDlg.wlKind = 'comm';
      ignoreDlg.wlMatch = (g.events || [])[0]?.event?.comm || '';
      ignoreDlg.wlDuration = '24h';
      ignoreDlg.wlUntil = '';
      ignoreDlg.title = `忽略 · ${g.container_id}`;
      ignoreDlg.show = true;
    }
    function openBatchIgnore() {
      const sel = groups.value.filter(g => selectedIds.value.includes(g.container_id));
      ignoreDlg.ids = sel.map(g => g.container_id);
      ignoreDlg.events = sel.reduce((n, g) => n + g.event_count, 0);
      ignoreDlg.decision = 'dismissed';
      ignoreDlg.reason = '';
      ignoreDlg.whitelist = false;
      ignoreDlg.wlKind = 'comm';
      ignoreDlg.wlMatch = '';
      ignoreDlg.wlDuration = '24h';
      ignoreDlg.wlUntil = '';
      ignoreDlg.title = `忽略 · 批量 ${sel.length} 组`;
      ignoreDlg.show = true;
    }
    function _calcUntil(dur, custom) {
      if (dur === '永久') return null;              // 不设时效 → 一直有效
      if (dur === 'custom') return custom || null;
      const mins = { '1h': 60, '24h': 1440, '7d': 10080 }[dur];
      const d = new Date(Date.now() + mins * 60000);
      const p = n => String(n).padStart(2, '0');
      return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
    }
    async function doIgnore() {
      const reason = ignoreDlg.reason.trim();
      if (!reason) return;
      const decision = ignoreDlg.decision;
      try {
        for (const cid of ignoreDlg.ids) {
          await post('/api/review/decision', {
            container_id: cid, decision, event_count: 1,
            note: reason, mode: ignoreDlg.whitelist ? 'whitelist' : 'manual',
          });
        }
        // 白名单写入（可含时限）
        if (ignoreDlg.whitelist && ignoreDlg.wlMatch) {
          const until = _calcUntil(ignoreDlg.wlDuration, ignoreDlg.wlUntil);
          await post('/api/whitelist', {
            kind: ignoreDlg.wlKind, match: ignoreDlg.wlMatch,
            valid_until: until || '', note: reason,
          });
          ElMessage.success(until ? `已加入白名单（至 ${until}）` : '已加入永久白名单');
        }
        const msg = decision === 'dismissed' ? '已驳回（误报）' : '已放行（ignored）';
        ElMessage.success(msg + (ignoreDlg.whitelist ? ' · 已加白名单' : ''));
        dropSelected(ignoreDlg.ids);
        ignoreDlg.show = false;
        load();
      } catch (e) { ElMessage.error(e.message); }
    }
    function dropSelected(ids) {
      const arr = Array.isArray(ids) ? ids : [ids];
      selectedIds.value = selectedIds.value.filter(i => !arr.includes(i));
    }

    // ---- 批量统一判决 ----
    async function batchDecide(decision) {
      for (const cid of [...selectedIds.value]) {
        const g = groups.value.find(g => g.container_id === cid);
        if (!g) continue;
        try {
          await post('/api/review/decision', { container_id: cid, decision, event_count: g.event_count });
        } catch (e) {}
      }
      const label = decision === 'confirmed' ? '已批量确认攻击' : '已批量处理';
      ElMessage.success(label + `（${selectedIds.value.length} 组）`);
      selectedIds.value = [];
      load();
    }

    usePolling(load, 3000);
    return {
      groups, decide: doConfirm, fmtTime, openNames, onExpand,
      selectedIds, allSelected, toggleSelect, toggleSelectAll, isSelected,
      confirmDlg, openConfirm, doConfirm,
      ignoreDlg, openIgnore, openBatchIgnore, doIgnore, batchDecide,
    };
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

    <!-- v0.6.4: 待确认资产横幅 — 存在 asset_state=PENDING_REVIEW 资产即提示 (ADR-050 人工确认闭环) -->
    <div v-if="pendingList.length" class="panel" style="display:flex;align-items:center;gap:10px;padding:10px 18px;border-color:var(--warn);background:rgba(245,158,11,.07)">
      <el-tag type="warning" effect="dark" size="small">{{ pendingList.length }}</el-tag>
      <span style="font-weight:600">个新资产待人工确认</span>
      <span style="font-size:12px;color:var(--muted)">拓扑中琥珀色虚线呼吸节点 = 待确认资产 · 确认后自动消隐并留痕</span>
      <div style="margin-left:auto;display:flex;gap:8px">
        <el-button size="small" type="warning" @click="openQueue">查看待确认队列</el-button>
        <el-button size="small" @click="trustAll">一键信任全部</el-button>
      </div>
    </div>

    <!-- 拓扑图 (v0.5.7): 蓝色星空背景, 节点=pod, 按 node 成簇, 服务关联连线 -->
    <div class="panel" style="display:flex;align-items:center;gap:12px;padding:10px 18px;flex-wrap:wrap;margin-bottom:0;border-bottom:none;border-radius:10px 10px 0 0">
      <span style="font-size:13px;color:var(--muted)">拓扑筛选:</span>
      <!-- v0.6.4: 改为「暂存 + 点按钮应用」。多选并列下, 每勾一项就重绘拓扑
           会让图反复跳动 (多选本质是"攒一组条件再查"), 故不再即时响应。
           条件改到 draftFilter, 点「应用筛选」时才提交到 topoFilter 并重绘。 -->
      <el-select v-model="draftFilter.nss" placeholder="命名空间" multiple collapse-tags
                 collapse-tags-tooltip filterable clearable
                 size="small" style="width:200px">
        <el-option v-for="ns in nsOptions" :key="ns" :label="ns" :value="ns" />
      </el-select>
      <el-select v-model="draftFilter.nodes" placeholder="节点" multiple collapse-tags
                 collapse-tags-tooltip clearable
                 size="small" style="width:180px">
        <el-option v-for="nd in data.nodes" :key="nd.name" :label="nd.name" :value="nd.name" />
      </el-select>
      <el-checkbox v-model="draftFilter.showInfra" size="small">公共服务圈</el-checkbox>
      <el-checkbox v-model="draftFilter.showPrivate" size="small">私有服务圈</el-checkbox>
      <el-select v-model="draftFilter.svc" placeholder="私有服务筛选" clearable size="small"
                 style="width:180px" :disabled="!draftFilter.showPrivate">
        <el-option v-for="s in privateSvcOptions" :key="s" :label="s" :value="s" />
      </el-select>
      <!-- v0.6.4: 待确认资产聚焦 (docker 容器无 ns/node 维度, 唯一可用筛选) -->
      <el-checkbox v-model="draftFilter.pendingOnly" size="small">仅显示待确认</el-checkbox>
      <!-- v0.6.5.2: 运行时筛选 — k8s 与 docker 可同机共存, 默认都显示;
           勾选后只显示对应运行时 (同时作用于拓扑与下方清单) -->
      <el-select v-model="draftFilter.runtimes" placeholder="运行时" multiple collapse-tags
                 collapse-tags-tooltip clearable size="small" style="width:170px">
        <el-option label="k8s Pod" value="k8s" />
        <el-option label="Docker 容器" value="docker" />
      </el-select>
      <!-- v0.6.4: 通用维度筛选 — 分级/镜像对 k8s pod 与 docker 容器同时生效。
           资产状态不在此筛选: 待确认已有顶部横幅 + 详情入口直达, 而"已覆盖"
           本就是"已确认 + 人工改级别"的一种, 三者不是并列的筛选维度 -->
      <!-- v0.6.4: 分级/镜像支持多选并列 — 单选无法表达「核心 + 重要」这类组合,
           而实际排查常需同时看多个分级 (或几个相关镜像), 故改为多选 -->
      <el-select v-model="draftFilter.levels" placeholder="资产分级" multiple collapse-tags
                 collapse-tags-tooltip clearable size="small" style="width:170px">
        <el-option v-for="lv in ASSET_LEVEL_OPTIONS" :key="lv"
                   :label="(LEVEL_LABELS[lv] || lv)" :value="lv" />
      </el-select>
      <el-select v-model="draftFilter.images" placeholder="镜像" multiple collapse-tags
                 collapse-tags-tooltip filterable clearable size="small" style="width:220px">
        <el-option v-for="img in imageOptions" :key="img" :label="img" :value="img" />
      </el-select>
      <div style="margin-left:auto;display:flex;gap:8px;align-items:center">
        <el-tag v-if="filterDirty" size="small" type="warning" effect="plain">条件已改, 未应用</el-tag>
        <el-button size="small" type="primary" @click="applyFilter">应用筛选</el-button>
        <el-button size="small" @click="resetTopoFilter">重置</el-button>
      </div>
      </div>
    <div class="panel topo-stars" style="position:relative;padding:0;overflow:hidden;border-radius:0 0 10px 10px">
      <div ref="topoRef" style="width:100%;height:420px"></div>
      <div style="position:absolute;top:12px;left:16px;font-size:13px;color:#8ea6c8;pointer-events:none">
        <span style="font-weight:600;color:#cbd5e1">资产拓扑</span>
        <span style="margin-left:10px">● 节点=pod/容器 · 按物理机成簇 · 琥珀虚线呼吸=待确认 · 命名空间着色</span>
      </div>
    </div>

    <!-- v0.6.4: 统一资产清单 — k8s pod 与 docker 容器同表展示。
         两者是同一类对象 (可发现/可确认/可覆盖/可查留痕), 只是数据来源不同:
         k8s 走 K8s API (有 namespace/node/pod_ip/services/labels),
         docker 走 Docker SDK (只有容器自身维度)。
         此前分成两张表、三列模板逐字重复, 且 docker 侧看不到"服务/Labels"等
         列的存在感, 用户难以建立"同一套资产模型"的认知。
         列设计: 类型列区分来源; k8s 专属列 (Pod IP/服务/Labels) 在 docker 行留空,
         避免为两种运行时各维护一份模板。 -->
    <div class="panel">

      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
        <h3 style="margin:0">📦 资产清单</h3>
        <el-tag size="small" type="info">{{ unifiedAssets.length }} 项</el-tag>
        <span class="sub" style="font-size:12px;color:var(--muted)">
          k8s {{ assetCounts.k8s }} · Docker {{ assetCounts.docker }}
          <template v-if="assetCounts.both">（同机共存，可按运行时筛选）</template>
        </span>
      </div>
      <el-table :data="unifiedAssets" size="small" stripe @row-click="openAsset">
        <el-table-column label="类型" width="86"><template #default="{row}">
          <el-tag size="small" :type="row.kind === 'k8s' ? 'primary' : 'warning'" effect="plain">
            {{ row.kind === 'k8s' ? 'Pod' : '容器' }}</el-tag></template></el-table-column>
        <el-table-column label="名称" min-width="200"><template #default="{row}">
          <span class="mono">{{ row.displayName }}</span>
          <div v-if="row.kind === 'docker' && row.id" style="font-size:11px;color:var(--muted)" class="mono">{{ row.id }}</div>
        </template></el-table-column>
        <el-table-column label="命名空间 / 节点" min-width="150"><template #default="{row}">
          <span v-if="row.namespace" class="mono" style="font-size:12px">{{ row.namespace }} / {{ row.node }}</span>
          <span v-else-if="row.nsKey" class="mono" style="font-size:12px">{{ row.nsKey }}</span>
          <span v-else style="color:var(--muted);font-size:12px">—</span>
        </template></el-table-column>
        <el-table-column label="镜像" min-width="210"><template #default="{row}">
          <span class="mono" style="font-size:12px">{{ row.image || '—' }}</span>
          <div v-if="row.imageCount > 1" style="font-size:11px;color:var(--muted)">+{{ row.imageCount - 1 }} 个镜像</div>
        </template></el-table-column>
        <el-table-column label="状态" width="105"><template #default="{row}">
          <el-tag size="small" :type="row.status === 'Running' ? 'success' : row.status === 'running' ? 'success' : row.status === 'Succeeded' ? 'info' : row.status === 'Failed' ? 'danger' : row.status === 'Pending' ? 'warning' : 'info'">{{ row.status }}</el-tag></template></el-table-column>
        <el-table-column label="IP 地址" width="120"><template #default="{row}">
          <span class="mono">{{ row.pod_ip || '—' }}</span></template></el-table-column>
        <el-table-column label="服务" min-width="130"><template #default="{row}">
          <el-tag v-for="s in (row.services || [])" :key="s" size="small" type="warning" style="margin-right:4px">{{ s }}</el-tag>
          <span v-if="!(row.services || []).length" style="color:var(--muted)">—</span></template></el-table-column>
        <el-table-column label="Labels" min-width="170"><template #default="{row}">
          <span style="font-size:12px;color:var(--muted)">{{ row.labelText || '—' }}</span></template></el-table-column>
        <el-table-column label="特权" width="72"><template #default="{row}">
          <el-tag v-if="row.privileged" size="small" type="danger">是</el-tag>
          <el-tag v-else size="small" type="primary">否</el-tag></template></el-table-column>
        <!-- v0.6.4: 资产分级/状态/操作列 (ADR-050 资产状态机前端接入) -->
        <el-table-column label="分级" width="155"><template #default="{row}">
          <el-tag v-if="row.level" size="small" :type="LEVEL_TYPES[row.level] || 'info'">
            {{ LEVEL_LABELS[row.level] || row.level }}<template v-if="row.level_source === 'override'"> ✋覆盖</template></el-tag>
          <span v-else style="color:var(--muted)">—</span></template></el-table-column>
        <el-table-column label="资产状态" width="105"><template #default="{row}">
          <el-tag v-if="row.asset_state" size="small" :type="ASSET_STATE_TYPES[row.asset_state] || 'info'">{{ ASSET_STATES[row.asset_state] || row.asset_state }}</el-tag>
          <span v-else style="color:var(--muted)">—</span></template></el-table-column>
        <el-table-column label="操作" width="230" fixed="right"><template #default="{row}">
          <template v-if="row.assetId">
            <el-button size="small" text type="primary" @click.stop="openAsset(row)">详情</el-button>
            <el-button v-if="row.asset_state === 'PENDING_REVIEW' && canWrite" size="small" type="warning" @click.stop="openConfirm(row)">确认</el-button>
            <el-button v-else-if="isAdmin" size="small" type="danger" @click.stop="openOverride(row)">覆盖</el-button>
            <el-button v-if="row.asset_state !== 'PENDING_REVIEW' && isAdmin" size="small" text type="warning" @click.stop="openRevert(row)">撤销</el-button>
            <el-button size="small" text type="primary" @click.stop="openAudit(row)">留痕({{ row.audit_count || 0 }})</el-button>
          </template></template></el-table-column>
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

    <!-- v0.6.4: 资产详情弹窗 — k8s pod 与 docker 容器统一入口
         (此前容器既无详情弹窗, 列表行也没有 row-click, 点击无反应) -->
    <el-dialog v-model="assetDialog.show" :title="assetDialog.title" width="560px">
      <template v-if="assetDialog.row">
        <!-- k8s pod 字段 -->
        <el-descriptions v-if="assetDialog.kind === 'k8s'" :column="2" size="small" border>
          <el-descriptions-item label="命名空间">{{ assetDialog.row.namespace }}</el-descriptions-item>
          <el-descriptions-item label="节点">{{ assetDialog.row.node }}</el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag size="small" :type="assetDialog.row.status === 'Running' ? 'success' : assetDialog.row.status === 'Succeeded' ? 'info' : assetDialog.row.status === 'Failed' ? 'danger' : assetDialog.row.status === 'Pending' ? 'warning' : 'info'">{{ assetDialog.row.status }}</el-tag></el-descriptions-item>
          <el-descriptions-item label="Pod IP"><span class="mono">{{ assetDialog.row.pod_ip || '—' }}</span></el-descriptions-item>
          <el-descriptions-item label="特权">
            <el-tag size="small" :type="assetDialog.row.privileged ? 'danger' : 'primary'">{{ assetDialog.row.privileged ? '是' : '否' }}</el-tag></el-descriptions-item>
          <el-descriptions-item label="创建">
            <span class="mono">{{ fmtTime(assetDialog.row.created) }}</span>
            <span v-if="assetAge(assetDialog.row.created)"
                  style="margin-left:8px;font-size:12px;color:var(--muted)">
              已运行 {{ assetAge(assetDialog.row.created) }}
            </span>
          </el-descriptions-item>
          <el-descriptions-item label="镜像" :span="2">
            <span v-for="img in assetDialog.row.images" :key="img" class="mono" style="display:block;font-size:12px">{{ img }}</span></el-descriptions-item>
          <el-descriptions-item label="所属服务" :span="2">
            <el-tag v-for="s in assetDialog.row.services" :key="s" size="small" type="warning" style="margin-right:4px">{{ s }}</el-tag>
            <span v-if="!assetDialog.row.services.length" style="color:var(--muted)">—</span></el-descriptions-item>
          <el-descriptions-item label="Labels" :span="2">
            <div style="font-size:12px;color:var(--muted)">
              <div v-for="(v,k) in assetDialog.row.labels" :key="k" class="mono">{{ k }} = {{ v }}</div>
            </div></el-descriptions-item>
        </el-descriptions>
        <!-- docker 容器字段 (无 namespace/node/labels, 展示 docker 自有维度) -->
        <el-descriptions v-else :column="2" size="small" border>
          <el-descriptions-item label="容器名"><span class="mono">{{ assetDialog.row.name }}</span></el-descriptions-item>
          <el-descriptions-item label="容器 ID"><span class="mono">{{ assetDialog.row.id }}</span></el-descriptions-item>
          <el-descriptions-item label="镜像" :span="2">
            <span class="mono" style="font-size:12px">{{ assetDialog.row.image || '—' }}</span></el-descriptions-item>
          <el-descriptions-item label="运行状态">
            <el-tag size="small" :type="assetDialog.row.status === 'running' ? 'success' : 'info'">{{ assetDialog.row.status }}</el-tag></el-descriptions-item>
          <el-descriptions-item label="特权">
            <el-tag size="small" :type="assetDialog.row.privileged ? 'danger' : 'primary'">{{ assetDialog.row.privileged ? '是' : '否' }}</el-tag></el-descriptions-item>
          <el-descriptions-item label="IP 地址" v-if="assetDialog.row.pod_ip">
            <span class="mono">{{ assetDialog.row.pod_ip }}</span></el-descriptions-item>
          <el-descriptions-item label="Labels" :span="2" v-if="assetDialog.row.labelsText">
            <div style="font-size:12px;color:var(--muted)">
              <div v-for="(v,k) in assetDialog.row.labels" :key="k" class="mono">{{ k }} = {{ v }}</div>
            </div></el-descriptions-item>
          <el-descriptions-item label="创建" :span="2">
            <span class="mono">{{ fmtTime(assetDialog.row.created) }}</span>
            <span v-if="assetAge(assetDialog.row.created)"
                  style="margin-left:8px;font-size:12px;color:var(--muted)">
              已运行 {{ assetAge(assetDialog.row.created) }}
            </span>
          </el-descriptions-item>
        </el-descriptions>
        <!-- v0.6.4: 资产状态机区 (ADR-050) — 两种运行时共用 -->
        <el-descriptions :column="1" size="small" border style="margin-top:10px">
          <el-descriptions-item v-if="assetDialog.row.asset_state" label="资产状态">
            <el-tag size="small" :type="ASSET_STATE_TYPES[assetDialog.row.asset_state] || 'info'">{{ ASSET_STATES[assetDialog.row.asset_state] || assetDialog.row.asset_state }}</el-tag>
            <el-tag v-if="assetDialog.row.level" size="small" :type="LEVEL_TYPES[assetDialog.row.level] || 'info'" style="margin-left:6px">
              {{ LEVEL_LABELS[assetDialog.row.level] || assetDialog.row.level }}<template v-if="assetDialog.row.level_source === 'override'"> ✋人工覆盖</template></el-tag>
            <el-button v-if="assetDialog.row.audit_count" size="small" text type="primary" style="margin-left:8px" @click="openAudit(assetDialog.row)">留痕({{ assetDialog.row.audit_count }})</el-button>
          </el-descriptions-item>
          <el-descriptions-item v-if="assetDialog.row.asset_rule" label="推断依据">
            <span class="mono" style="font-size:12px;color:var(--warn)">{{ assetDialog.row.asset_rule }}</span></el-descriptions-item>
          <el-descriptions-item v-else-if="assetDialog.row.level" label="推断依据">
            <span class="mono" style="font-size:12px;color:var(--muted)">未命中分级规则 · 兜底 medium</span></el-descriptions-item>
        </el-descriptions>
      </template>
      <template #footer>
        <div style="display:flex;align-items:center">
          <el-button v-if="assetDialog.row && assetDialog.row.asset_state === 'PENDING_REVIEW' && canWrite"
                     type="warning" @click="openConfirm(assetDialog.row)">确认信任该资产</el-button>
          <!-- v0.6.4: 已决策资产仍可再次覆盖 (admin) — 此前只在待确认时给入口,
               确认/覆盖后无法再改, 与「人工可修正自动推断」的闭环意图相悖 -->
          <el-button v-if="assetDialog.row && assetDialog.row.asset_state !== 'PENDING_REVIEW' && isAdmin"
                     type="danger" @click="openOverride(assetDialog.row)">修改覆盖级别</el-button>
          <!-- v0.6.4: 撤销 — 防误操作, 让资产重回待确认 -->
          <el-button v-if="assetDialog.row && assetDialog.row.asset_state !== 'PENDING_REVIEW' && isAdmin"
                     type="warning" plain @click="openRevert(assetDialog.row)">撤销</el-button>
          <div style="flex:1"></div>
          <el-button @click="assetDialog.show = false">关闭</el-button>
        </div>
      </template>
    </el-dialog>

    <!-- v0.6.4: 资产确认弹窗 — 推断依据 + 原因输入; admin 可附加级别覆盖 (ADR-050) -->
    <el-dialog v-model="confirmDialog.show" :title="confirmDialog.title" width="640px">
      <template v-if="confirmDialog.asset">
        <el-descriptions :column="2" size="small" border style="margin-bottom:12px">
          <el-descriptions-item label="资产">
            <span class="mono">{{ confirmDialog.asset.name }}</span></el-descriptions-item>
          <el-descriptions-item label="类型">
            <el-tag size="small" :type="confirmDialog.asset.kind === 'k8s' ? 'primary' : 'success'">{{ confirmDialog.asset.kind === 'k8s' ? 'Pod' : '容器' }}</el-tag></el-descriptions-item>
          <el-descriptions-item label="镜像" :span="2">
            <span class="mono" style="font-size:12px">{{ confirmDialog.asset.image || '—' }}</span></el-descriptions-item>
          <el-descriptions-item label="当前状态">
            <el-tag size="small" :type="ASSET_STATE_TYPES[confirmDialog.asset.state] || 'info'">{{ ASSET_STATES[confirmDialog.asset.state] || confirmDialog.asset.state }}</el-tag></el-descriptions-item>
          <el-descriptions-item label="推断级别">
            <el-tag size="small" :type="LEVEL_TYPES[confirmDialog.asset.level] || 'info'">{{ LEVEL_LABELS[confirmDialog.asset.level] || confirmDialog.asset.level }}</el-tag></el-descriptions-item>
          <el-descriptions-item label="命中规则" :span="2">
            <span class="mono" style="font-size:12px;color:var(--warn)">{{ confirmDialog.asset.rule || '—' }}</span></el-descriptions-item>
        </el-descriptions>
        <div style="font-size:13px;color:var(--muted);margin-bottom:10px">
          <template v-if="confirmDialog.mode === 'override'">
            覆盖即把级别改为人工值、状态转「已覆盖」并写入留痕（人工决策 + 状态变迁 + 级别来源变迁）。可重复修改，每次均留痕。
          </template>
          <template v-else>
            确认即转为「已确认」并写入留痕（三段式: 自动推断 → 人工决策 → 状态变迁）。建议填写原因，便于审计追溯。
          </template>
        </div>
        <el-input type="textarea" :rows="2" v-model="confirmDialog.reason"
                  :placeholder="confirmDialog.mode === 'override' ? '覆盖原因（必填，审计追溯用）' : '确认原因（可选，admin 覆盖级别时必填）'" />
        <template v-if="isAdmin">
          <div style="display:flex;align-items:center;gap:10px;margin-top:12px">
            <span style="font-size:13px;font-weight:600">级别覆盖 (admin):</span>
            <el-select v-model="confirmDialog.overrideLevel" placeholder="选择覆盖级别" size="small" style="width:180px" clearable>
              <el-option v-for="lv in ASSET_LEVEL_OPTIONS" :key="lv" :label="(LEVEL_LABELS[lv] || lv) + ' (' + lv + ')'" :value="lv" />
            </el-select>
            <span style="font-size:12px;color:var(--muted)">选择后走 /override，状态为「已覆盖」</span>
          </div>
        </template>
      </template>
      <template #footer>
        <el-button @click="confirmDialog.show = false">取消</el-button>
        <!-- 确认模式给「确认信任」; 覆盖模式 (admin 二次修正) 只给「保存覆盖」 -->
        <el-button v-if="confirmDialog.mode === 'confirm'" type="warning" @click="doConfirm">确认信任</el-button>
        <el-button v-if="isAdmin" type="danger"
                   :disabled="!confirmDialog.overrideLevel || !confirmDialog.reason.trim()"
                   @click="doOverride">
          {{ confirmDialog.mode === 'override' ? '保存覆盖' : '覆盖级别确认' }}
        </el-button>
      </template>
    </el-dialog>

    <!-- v0.6.4: 待确认队列 — 勾选批量一键信任 (方案A: 前端循环逐条 confirm, 留痕按资产分条) -->
    <el-dialog v-model="queueDialog.show" title="待确认资产队列" width="860px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap">
        <el-tag type="warning" effect="dark">{{ queueDialog.selected.length }} / {{ pendingList.length }}</el-tag>
        <span style="font-size:13px">已勾选待确认</span>
        <el-input v-model="queueDialog.reason" placeholder="统一确认原因（可选，写则批量留痕共用）" size="small" style="width:280px;flex:1" clearable />
        <el-button size="small" type="warning" :disabled="!queueDialog.selected.length" @click="batchTrust">一键信任所选 ({{ queueDialog.selected.length }})</el-button>
      </div>
      <el-table :data="pendingList" size="small" stripe max-height="420" @selection-change="onQueueSelect">
        <el-table-column type="selection" width="42" />
        <el-table-column label="资产" min-width="180"><template #default="{row}">
          <span class="mono">{{ row.name }}</span></template></el-table-column>
        <el-table-column label="类型" width="80"><template #default="{row}">
          <el-tag size="small" :type="row.kind === 'k8s' ? 'primary' : 'success'">{{ row.kind === 'k8s' ? 'Pod' : '容器' }}</el-tag></template></el-table-column>
        <el-table-column label="推断级别" width="100"><template #default="{row}">
          <el-tag size="small" :type="LEVEL_TYPES[row.level] || 'info'">{{ LEVEL_LABELS[row.level] || row.level }}</el-tag></template></el-table-column>
        <el-table-column label="推断依据" min-width="220"><template #default="{row}">
          <span class="mono" style="font-size:12px;color:var(--warn)">{{ row.rule || '—' }}</span></template></el-table-column>
        <el-table-column label="留痕" width="90"><template #default="{row}">
          <el-button size="small" text type="primary" @click="openAudit(row)">{{ row.auditCount || 0 }} 条</el-button></template></el-table-column>
        <el-table-column label="操作" width="110" fixed="right"><template #default="{row}">
          <el-button size="small" type="warning" @click="openConfirm(row)">确认</el-button></template></el-table-column>
      </el-table>
    </el-dialog>

    <!-- v0.6.4: 资产留痕弹窗 — 三段式审计 (auto_inference / human_decision / status_transition) -->
    <el-dialog v-model="auditDialog.show" :title="auditDialog.title" width="720px">
      <el-empty v-if="!auditGroups.length" description="暂无留痕" />
      <!-- v0.6.4: 一次决策会写多条留痕 (human_decision + status_transition×N),
           语义上是同一事件的不同侧面。此前平铺展示, 看起来像多次独立操作,
           故按 event_id 聚合为「决策卡片」: 一卡 = 一次决策, 卡内列侧面。
           存量数据无 event_id → 退回 ts+type 分组兜底 -->
      <el-timeline v-else style="padding-left:6px">
        <el-timeline-item v-for="(g, gi) in auditGroups" :key="gi"
                          :timestamp="fmtTime(g.ts)" :type="auditTypeOf(g.main)">
          <div style="font-size:13px">
            <el-tag size="small" :type="auditTypeOf(g.main)" style="margin-right:8px">{{ auditLabel(g.main) }}</el-tag>
            <template v-if="g.main.detail && g.main.detail.by">
              <span class="mono" style="margin-right:8px">{{ g.main.detail.by }}</span>
            </template>
            <span class="mono" style="font-size:12px;color:var(--muted)">{{ auditText(g.main) }}</span>
          </div>
          <!-- 同一决策的其余侧面 (状态变迁 / 级别来源变迁) 折叠在下方 -->
          <div v-if="g.subs.length" style="margin-top:6px;padding-left:10px;border-left:2px solid var(--border)">
            <div v-for="(s, si) in g.subs" :key="si"
                 style="font-size:12px;color:var(--muted);line-height:1.8">
              <el-tag size="small" effect="plain" style="margin-right:6px">{{ auditLabel(s) }}</el-tag>
              <span class="mono">{{ auditText(s) }}</span>
            </div>
            <div style="font-size:11px;color:var(--muted);margin-top:2px">
              同一次决策（{{ g.subs.length + 1 }} 条留痕）
            </div>
          </div>
        </el-timeline-item>
      </el-timeline>
    </el-dialog>
  </div>`,
  setup() {
    const data = reactive({ runtime: '', total: 0, nodes: [], services: [], containers: [], error: '' });
    // v0.6.4: 统一资产详情弹窗 (k8s pod + docker 容器共用, kind 决定字段集)
    const assetDialog = reactive({ show: false, row: null, title: '', kind: 'k8s' });
    const topoRef = ref(null);
    let chart = null;
    let lastTopoKey = '';  // 轮询去重: 数据未变不重建图 (布局稳定)

    // v0.6.4: 资产确认闭环 (ADR-050) — 角色权限: operator+ confirm, admin 另可 override, analyst 只读
    const _me = JSON.parse(localStorage.getItem('guard_me') || '{}');
    const canWrite = _me.role === 'admin' || _me.role === 'operator';
    const isAdmin = _me.role === 'admin';
    const pendingList = ref([]);   // 归一化待确认资产 (asset_state === PENDING_REVIEW)
    let _seenAssets = null;        // 新资产轮询提示: 首轮静默, 只对增量提醒
    // v0.6.4: mode = 'confirm' (待确认→已确认) | 'override' (admin 覆盖级别, 可重复)
    const confirmDialog = reactive({ show: false, title: '', asset: null, reason: '', overrideLevel: '', mode: 'confirm' });
    const queueDialog = reactive({ show: false, reason: '', selected: [] });
    const auditDialog = reactive({ show: false, title: '', rows: [] });

    // 归一化资产流: k8s pods + docker containers → 统一资产对象 (assetId 一致)
    function collectAssets() {
      const out = [];
      data.nodes.forEach(nd => (nd.pods || []).forEach(p => {
        if (!p.asset_id) return;  // 未纳入资产库的 pod 不参与确认闭环
        out.push({
          assetId: p.asset_id, kind: 'k8s', name: p.namespace + '/' + p.name,
          node: nd.name, image: (p.images && p.images[0]) || '',
          level: p.level, levelSource: p.level_source, state: p.asset_state,
          rule: p.asset_rule, auditCount: p.audit_count || 0,
        });
      }));
      (data.containers || []).forEach(c => {
        if (!c.id) return;
        out.push({
          assetId: c.id, kind: 'docker', name: c.name, node: '',
          image: c.image || '',
          level: c.level, levelSource: c.level_source, state: c.asset_state,
          rule: c.asset_rule, auditCount: c.audit_count || 0,
        });
      });
      return out;
    }

    // 轮询同步待确认队列 + 增量消息提示 (不自动轰炸, 点通知直达队列)
    function syncPending() {
      const fresh = collectAssets().filter(a => a.state === 'PENDING_REVIEW');
      if (_seenAssets) {
        const have = new Set(_seenAssets);
        const added = fresh.filter(a => !have.has(a.assetId));
        if (added.length) {
          ElNotification({
            type: 'warning', duration: 5000,
            title: '发现 ' + added.length + ' 个新资产待确认',
            message: added[0].name + (added.length > 1 ? ' 等 ' + added.length + ' 项' : '') + ' — 拓扑中琥珀虚线呼吸节点, 请人工确认',
            onClick: () => { openQueue(); },
          });
        }
      }
      _seenAssets = fresh.map(a => a.assetId);
      pendingList.value = fresh;
    }

    // v0.5.7: 拓扑图 — ECharts 关系图
    //  节点=pod (按命名空间着色) + service (金色菱形)
    //  按 node 成簇; 公共依赖服务 (kube-dns/metrics-server) 默认折叠连线
    //  筛选: 命名空间/节点/仅服务关联
    // v0.6.4: pendingOnly — 只看待确认资产 (docker 无 ns/node 维度, 靠此项筛选)
    // v0.6.4: ns/node/level/image 均为**数组** (多选并列筛选)。
    //   单选无法表达「核心 + 重要」或「default + kube-system」这类组合,
    //   而实际排查常需同时看多个取值。空数组 = 不限制。
    const topoFilter = reactive({ nss: [], nodes: [], showInfra: false, showPrivate: false,
                                  svc: '', pendingOnly: false,
                                  // v0.6.4: docker 容器可用维度 (无 ns/node, 靠分级/镜像筛)
                                  levels: [], images: [],
                                  // v0.6.5.2: 运行时显隐 — k8s 与 docker 可同机共存,
                                  //   默认空数组 = 全显示; 可只勾其中一个
                                  runtimes: [] });
    // 筛选草稿: 下拉里改的是它, 点「应用筛选」才提交到 topoFilter。
    //   多选并列下即时重绘会让拓扑反复跳动, 且每勾一项都触发一次
    //   ECharts 重排 — 攒够条件再一次性应用, 交互与性能都更合理。
    const draftFilter = reactive(JSON.parse(JSON.stringify(topoFilter)));
    // 草稿与已应用条件是否有差异 → 决定是否提示「未应用」
    const filterDirty = computed(() =>
      JSON.stringify(Object.keys(topoFilter).sort().map(k => [k, topoFilter[k]]))
      !== JSON.stringify(Object.keys(draftFilter).sort().map(k => [k, draftFilter[k]])));
    function applyFilter() {
      Object.assign(topoFilter, JSON.parse(JSON.stringify(draftFilter)));
      buildTopoDebounced();
    }
    const nsOptions = ref([]);
    const imageOptions = ref([]);
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
      // 筛选: 过滤 pod / 容器 (v0.6.4: docker 容器同样入图 — 此前只画
      // k8s pod, docker 单机形态下拓扑为空, 待确认闪烁无从体现)
      const nodeGroups = [];
      // v0.6.4: 通用维度谓词 — k8s pod 与 docker 容器共用。
      //   ns/node 是 k8s 专属维度: docker 容器无 namespace, 遇 ns 筛选时跳过该
      //   条件而非"整组隐藏" (否则容器永远筛不到, 只能靠开关全关)
      const assetImage = (it) => it.image || (it.images && it.images[0]) || '';
      // nsKey 由调用方显式传入 (k8s pod → namespace; docker 容器 → 伪命名空间
      // 'docker'), 不再用 guess。docker 容器只能来自被监控的这台机器,
      // 不存在"其他机器的 docker", 故归类到 'docker' 伪命名空间即可,
      // 不必单独给显隐开关。
      const matchFilter = (it, nsKey, nodeName, runtime) =>
        inSet(topoFilter.runtimes, runtime)
        && inSet(topoFilter.nss, nsKey)
        && (!nodeName || inSet(topoFilter.nodes, nodeName))
        && (!topoFilter.pendingOnly || it.asset_state === 'PENDING_REVIEW')
        && inSet(topoFilter.levels, it.level)
        && inSet(topoFilter.images, assetImage(it));
      const filteredNodes = data.nodes
        .filter(nd => inSet(topoFilter.nodes, nd.name))
        .map(nd => {
          const pods = nd.pods.filter(p => matchFilter(p, p.namespace, nd.name, 'k8s'));
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
            // v0.6.4: 待确认资产 → 琥珀虚线边框 (ADR-050), 闪烁由 blink 定时器驱动
            itemStyle: p.asset_state === 'PENDING_REVIEW'
              ? { color: NS_COLORS[p.namespace] || '#64748b',
                  borderColor: '#f59e0b', borderWidth: 2, borderType: 'dashed',
                  shadowColor: '#f59e0b', shadowBlur: 0 }
              : { color: NS_COLORS[p.namespace] || '#64748b' },
            __pending: p.asset_state === 'PENDING_REVIEW',
            __pod: p,
          });
        });
      });
      // docker 模式: 容器入图 (无 namespace/node 维度 → 归入"本地 docker"组)。
      //   v0.6.4: 显隐由 showDocker 总开关 + 通用维度 (分级/状态/镜像) 共同控制 —
      //   此前 ns/node 一选就整组消失, 容器侧没有任何可用筛选
      const containers = (data.containers || [])
        .filter(c => c.id && matchFilter(c, DOCKER_NS, null, 'docker'));
      if (containers.length) {
        const gname = DOCKER_GROUP;
        if (!nodeGroups.includes(gname)) nodeGroups.push(gname);
        const gi = nodeGroups.indexOf(gname);
        containers.forEach(c => {
          const key = 'docker/' + c.id;
          nodeIdx[key] = nodes.length;
          nodes.push({
            id: key, name: c.name,
            symbolSize: c.privileged ? 34 : 24,
            category: gi,
            itemStyle: c.asset_state === 'PENDING_REVIEW'
              ? { color: NS_COLORS[''] || '#3b82f6',
                  borderColor: '#f59e0b', borderWidth: 2, borderType: 'dashed',
                  shadowColor: '#f59e0b', shadowBlur: 0 }
              : { color: NS_COLORS[''] || '#3b82f6' },
            __pending: c.asset_state === 'PENDING_REVIEW',
            __container: c,
          });
        });
      }
      data.services.forEach(s => {
        if (!inSet(topoFilter.nss, s.namespace)) return;
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
      const groups = nodeGroups.slice();   // v0.6.4: 含 docker 组 (末位)
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
        // v0.6.4: 末位 docker 组取容器清单; 其余按 k8s node 组取 pods
        const isDocker = g === DOCKER_GROUP;
        const items = isDocker ? containers
                               : ((filteredNodes[gi] && filteredNodes[gi].pods) || []);
        if (!items.length) return;
        const angle = (2 * Math.PI * gi) / Math.max(groups.length, 1) - Math.PI / 2;
        const cx = topoW * 0.5 + topoW * 0.28 * Math.cos(angle);
        const cy = topoH * 0.5 + topoH * 0.3 * Math.sin(angle);
        const n = items.length;
        items.forEach((p, pi) => {
          const key = isDocker ? 'docker/' + p.id : p.namespace + '/' + p.name;
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
      const key = JSON.stringify({ nodes: nodes.map(n => n.id + n.symbolSize + (n.category||'') + (n.itemStyle?.shadowColor||'') + (n.__pending ? '~P' : '')),
                                    legend: legendGraphics.map(g => JSON.stringify(g.children)),
                                    svc: topoFilter.svc });
      if (key === lastTopoKey) return;
      lastTopoKey = key;
      // 首次全量配置, 之后增量更新 data
      if (!chart.__topoInit) {
        chart.setOption({
          backgroundColor: 'transparent',
          tooltip: { trigger: 'item',
            formatter: (p) => {
              if (p.data?.__pod) {
                const d = p.data.__pod;
                return `${d.namespace}/${d.name}\n状态: ${d.status}\n`
                  + `分级: ${LEVEL_LABELS[d.level] || d.level || '—'}\n`
                  + `资产状态: ${ASSET_STATES[d.asset_state] || d.asset_state || '—'}\n`
                  + `服务: ${d.services.join(',') || '无'}`;
              }
              if (p.data?.__container) {
                const d = p.data.__container;
                return `${d.name}\n镜像: ${d.image || '—'}\n状态: ${d.status}\n`
                  + `分级: ${LEVEL_LABELS[d.level] || d.level || '—'}`
                  + `${d.level_source === 'override' ? ' (人工覆盖)' : ''}\n`
                  + `资产状态: ${ASSET_STATES[d.asset_state] || d.asset_state || '—'}\n`
                  + `依据: ${d.asset_rule || '兜底 medium'}`;
              }
              return p.data.id || p.name;
            } },
          graphic: legendGraphics,
          series: [{
            type: "graph", layout: "none", roam: true, draggable: false,
            label: { show: true, fontSize: 10, color: "#cbd5e1" },
            animation: false,
            emphasis: { focus: 'adjacency' },
          }],
        }, { replaceMerge: ['graphic'] });
        chart.__topoInit = true;
        // v0.6.4: 点击节点 (pod 或 docker 容器) → 统一开资产详情弹窗,
        //   确认/覆盖/留痕三个动作作为弹窗内按钮给出。
        //   此前容器节点被分流到留痕弹窗, 用户点圆圈看不到任何详情
        chart.off('click');
        chart.on('click', (params) => {
          if (params.data && params.data.__pod) {
            openAssetDetail(params.data.__pod);
          } else if (params.data && params.data.__container) {
            openAssetDetail(params.data.__container);
          }
        });
      }
      chart.setOption({
        legend: { data: groups, textStyle: { color: '#8ea6c8' },
                  bottom: 4, itemWidth: 12, itemHeight: 12 },
        graphic: legendGraphics,
        series: [{
          type: "graph", layout: "none", roam: true, draggable: false,
          label: { show: true, fontSize: 10, color: "#cbd5e1" },
          animation: false,
          categories: groups.map(n => ({ name: n })),
          data: nodes,
          links: [],
        }],
      }, { replaceMerge: ['graphic'] });  // 清空旧 graphic (图例随开关消失)
      // v0.6.4: 存在待确认节点 → 启动呼吸闪烁; 无则停止 (确认后自动消隐)
      chart.__topoNodes = nodes;
      if (nodes.some(n => n.__pending)) startBlink(); else stopBlink();
    }

    // v0.6.4: 待确认节点呼吸闪烁 — 增量改 shadowBlur, 不重建图 (布局/roam 稳定)
    let _blinkTimer = null;
    let _blinkOn = false;
    function stopBlink() {
      if (_blinkTimer) { clearInterval(_blinkTimer); _blinkTimer = null; }
    }
    function startBlink() {
      if (_blinkTimer || !chart) return;
      _blinkTimer = setInterval(() => {
        if (!chart || !chart.__topoNodes) return;
        _blinkOn = !_blinkOn;
        const data = chart.__topoNodes.map(n => n.__pending
          ? { ...n, itemStyle: { ...n.itemStyle, shadowBlur: _blinkOn ? 16 : 0 } }
          : n);
        chart.setOption({ series: [{ type: 'graph', layout: 'none', data }] });
      }, 800);
    }

    // v0.5.7: 关闭私有服务圈时清空筛选 + 重建图 (筛选是开关子功能)
    function onPrivateToggle() {
      if (!topoFilter.showPrivate) topoFilter.svc = '';
      buildTopoDebounced();
    }

    // v0.6.4: 清空拓扑筛选 (k8s 维度 + docker 可用维度 + 容器显隐开关)
    function resetTopoFilter() {
      // 清空已应用条件 + 草稿 (两者不一致会让"重置"看起来没生效)
      Object.assign(topoFilter, {
        nss: [], nodes: [], showInfra: false, showPrivate: false,
        svc: '', pendingOnly: false, levels: [], images: [],
      });
      Object.assign(draftFilter, JSON.parse(JSON.stringify(topoFilter)));
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
        const imgs = new Set();
        data.nodes.forEach(nd => nd.pods.forEach(p => {
          nss.add(p.namespace);
          p.images.forEach(i => i && imgs.add(i));
        }));
        // v0.6.4: 镜像选项含 docker 容器镜像 — 容器侧筛选可用
        (data.containers || []).forEach(c => c.image && imgs.add(c.image));
        // docker 容器归入伪命名空间 'docker', 与 k8s namespace 并列可选
        if ((data.containers || []).length) nss.add(DOCKER_NS);
        nsOptions.value = [...nss].sort();
        imageOptions.value = [...imgs].sort();
        syncPending();   // v0.6.4: 待确认队列 + 新资产增量提示
        buildTopo();
      } catch (e) {}
    }
    const refresh = load;
    function showPod(row) { openAssetDetail(row); }   // 兼容旧调用点 (pod 表格)

    // ---- v0.6.4: 资产确认闭环方法 (ADR-050) ----
    // 行数据(pod/容器原始行 或 归一资产对象) → 统一提取资产字段
    function pickAsset(row) {
      const assetId = row.asset_id || row.assetId || row.id;
      return {
        assetId: assetId,
        kind: row.kind || (row.namespace ? 'k8s' : 'docker'),
        name: row.namespace && row.name ? row.namespace + '/' + row.name : (row.name || assetId),
        image: row.image || (row.images && row.images[0]) || '',
        level: row.level, state: row.asset_state || row.state,
        rule: row.asset_rule || row.rule,
        auditCount: row.audit_count || row.auditCount || 0,
      };
    }
    // v0.6.4: 资产点击统一入口 — 一律开详情弹窗 (与 k8s pod 体验一致)。
    //   确认/覆盖/留痕三个动作都在详情弹窗里给按钮, 而不是由点击手势猜意图:
    //   此前 docker 容器点击被分流到 openAudit, 用户点了却看不到任何详情
    function openAsset(row) {
      const r = row.__pod || row.__container || row;
      openAssetDetail(r);
    }
    function openAssetDetail(row) {
      assetDialog.row = row;
      assetDialog.kind = row.namespace ? 'k8s' : 'docker';
      assetDialog.title = '资产详情 — '
        + (row.namespace ? row.namespace + '/' + row.name : (row.name || row.id));
      assetDialog.show = true;
    }
    // v0.6.4: 撤销确认/覆盖 → 资产重回 PENDING_REVIEW (防误操作)。
    //   权限与 override 一致 (admin): 撤销会让资产重新进入待确认队列并恢复
    //   闪烁提示, 属于"推翻已生效决策", 不能放开给 operator。
    //   级别不回滚 — 人工覆盖过的级别是有价值信息, 撤销只回退确认状态。
    function openRevert(row) {
      if (!isAdmin) { ElMessage.warning('仅管理员 (admin) 可撤销'); return; }
      if ((row.asset_state || row.state) === 'PENDING_REVIEW') {
        ElMessage.warning('该资产本就处于待确认状态'); return;
      }
      ElMessageBox.prompt(
        '撤销后资产将重新进入待确认队列并恢复闪烁提示, 需重新确认。'
        + '（级别保留人工值, 不回滚）',
        '撤销确认 — ' + (row.name || row.id),
        { confirmButtonText: '确认撤销', cancelButtonText: '取消',
          inputPlaceholder: '撤销原因（审计追溯用）', inputType: 'textarea' }
      ).then(async ({ value }) => {
        const reason = (value || '').trim();
        if (!reason) { ElMessage.warning('撤销必须填写原因'); return; }
        try {
          await post('/api/assets/' + encodeURIComponent(
            row.asset_id || row.assetId || row.id) + '/revert', { reason });
          ElMessage.success('已撤销: 资产回到待确认');
          refresh();
        } catch (e) { ElMessage.error('撤销失败: ' + e.message); }
      }).catch(() => {});
    }
    // 确认: 仅待确认资产 (PENDING_REVIEW → CONFIRMED), operator+ 可用
    function openConfirm(row) {
      if (!canWrite) { ElMessage.warning('只读角色 (analyst) 无确认权限'); return; }
      if ((row.asset_state || row.state) !== 'PENDING_REVIEW') {
        ElMessage.warning('该资产已决策, 如需修改请点「覆盖」'); return;
      }
      openDecision(row, 'confirm');
    }
    // v0.6.4: 覆盖 — admin 对任意已入库资产可再次修改级别 (支持二次修正)。
    //   此前仅限待确认状态, 确认后无法再改, 闭环断了半截
    function openOverride(row) {
      if (!isAdmin) { ElMessage.warning('仅管理员 (admin) 可覆盖级别'); return; }
      openDecision(row, 'override');
    }
    function openDecision(row, mode) {
      const a = pickAsset(row);
      confirmDialog.asset = a;
      confirmDialog.mode = mode;
      confirmDialog.title = (mode === 'override' ? '修改覆盖级别 — ' : '资产确认 — ') + a.name;
      confirmDialog.reason = '';
      // 覆盖模式默认带出当前级别, 便于在现值基础上改
      confirmDialog.overrideLevel = mode === 'override' ? (a.level || '') : '';
      confirmDialog.show = true;
    }
    async function doConfirm() {
      const a = confirmDialog.asset;
      if (!a) return;
      try {
        const res = await post('/api/assets/' + encodeURIComponent(a.assetId) + '/confirm',
          { reason: confirmDialog.reason.trim() });
        ElMessage.success('已确认 ' + a.name + ' → ' + (ASSET_STATES[res.state] || res.state));
        confirmDialog.show = false;
        refresh();
      } catch (e) { ElMessage.error('确认失败: ' + e.message); }
    }
    async function doOverride() {
      const a = confirmDialog.asset;
      if (!a || !confirmDialog.overrideLevel) return;
      if (!confirmDialog.reason.trim()) { ElMessage.warning('覆盖必须填写原因'); return; }
      try {
        const res = await post('/api/assets/' + encodeURIComponent(a.assetId) + '/override',
          { level: confirmDialog.overrideLevel, reason: confirmDialog.reason.trim() });
        ElMessage.success('已覆盖 ' + a.name + ' → ' + (LEVEL_LABELS[res.level] || res.level)
          + ' (状态: ' + (ASSET_STATES[res.state] || res.state) + ')');
        confirmDialog.show = false;
        refresh();
      } catch (e) { ElMessage.error('覆盖失败: ' + e.message); }
    }
    // v0.6.4: 筛选同时作用于下方清单 — 此前只过滤拓扑, 列表照旧全量展示,
    //   用户选了镜像却看到列表纹丝不动, 自然判定"筛选没用"。
    //   注意: showDocker 只管拓扑显隐, 不参与列表 (列表是主信息区, 不该被隐藏)
    function matchAsset(it) {
      const img = it.image || (it.images && it.images[0]) || '';
      const nsKey = it.nsKey || it.namespace || DOCKER_NS;
      return inSet(topoFilter.runtimes, it.kind)
        && inSet(topoFilter.nss, nsKey)
        && (!it.node || inSet(topoFilter.nodes, it.node))
        && (!topoFilter.pendingOnly || it.asset_state === 'PENDING_REVIEW')
        && inSet(topoFilter.levels, it.level)
        && inSet(topoFilter.images, img);
    }
    // v0.6.4: 统一资产行 — 把 k8s pod 与 docker 容器归一化成同构对象。
    //   两者是同一类资产 (可发现/可确认/可覆盖/可查留痕), 差异只在数据来源:
    //     k8s  : namespace / node / pod_ip / services / labels / images[]
    //     docker: 只有容器自身维度 → 上述字段留空, 列表显示 —
    //   归一化后 UI 只需一套列模板, 后续 v0.6.7 六层审计也只需接一处。
    const unifiedAssets = computed(() => {
      const out = [];
      // k8s pod (按物理机分组, node 筛选在此生效)
      data.nodes.forEach(nd => (nd.pods || []).forEach(p => {
        if (!inSet(topoFilter.nodes, nd.name)) return;
        const images = p.images || [];
        const row = {
          kind: 'k8s',
          id: p.asset_id || p.name,
          name: p.name,
          displayName: p.namespace ? `${p.namespace}/${p.name}` : p.name,
          namespace: p.namespace || '',
          nsKey: p.namespace || '',
          node: nd.name || '',
          image: images[0] || '',
          imageCount: images.length,
          status: p.status,
          pod_ip: p.pod_ip || '',
          services: p.services || [],
          labelText: Object.entries(p.labels || {}).slice(0, 3)
            .map(([k, v]) => `${k}=${v}`).join(' ') || '',
          privileged: !!p.privileged,
          created: p.created,
          labels: p.labels || {},
          labelsText: Object.entries(p.labels || {}).slice(0, 3)
            .map(([k, v]) => `${k}=${v}`).join(' ') || '',
          level: p.level, level_source: p.level_source,
          asset_state: p.asset_state, asset_rule: p.asset_rule,
          audit_count: p.audit_count,
        };
        row.assetId = p.asset_id || pickAsset(p).assetId;
        if (matchAsset(row)) out.push(row);
      }));
      // docker 容器 (无 namespace/node/pod_ip/services/labels)
      (data.containers || []).forEach(c => {
        const row = {
          kind: 'docker',
          id: c.id,
          name: c.name,
          displayName: c.name,
          namespace: '', nsKey: DOCKER_NS, node: '',
          image: c.image || '',
          imageCount: c.image ? 1 : 0,
          status: c.status,
          // docker 同样有 IP 与 labels (compose 元数据), 不再一律留空
          pod_ip: c.ip || '',
          services: c.labels && c.labels['com.docker.compose.service']
            ? [c.labels['com.docker.compose.service']] : [],
          labelText: Object.entries(c.labels || {}).slice(0, 3)
            .map(([k, v]) => `${k}=${v}`).join('') || '',
          privileged: !!c.privileged,
          created: c.created,
          labels: c.labels || {},
          labelsText: Object.entries(c.labels || {}).slice(0, 3)
            .map(([k, v]) => `${k}=${v}`).join(' ') || '',
          level: c.level, level_source: c.level_source,
          asset_state: c.asset_state, asset_rule: c.asset_rule,
          audit_count: c.audit_count,
        };
        row.assetId = c.asset_id || c.id;
        if (matchAsset(row)) out.push(row);
      });
      return out;
    });

    // v0.6.5.2: 运行时计数 (按原始数据, 不随筛选变) — 顶部展示同机
    //   共存时各有几项; both=true 表示两种运行时都采集到了。
    const assetCounts = computed(() => {
      const k8s = (data.nodes || [])
        .reduce((n, nd) => n + ((nd.pods || []).length), 0);
      const docker = (data.containers || []).length;
      return { k8s, docker, both: (data.runtimes || []).length > 1 };
    });

    // v0.6.4: 留痕按「决策事件」聚合。
    //   后端 confirm 写 2 条、override 写 3 条 (human_decision + status_transition×N),
    //   它们同 ts 同 event_id, 属一次决策。平铺会让用户误以为被操作了多次。
    //   策略: event_id 优先; 存量数据无该字段 → 用 ts 兜底 (同毫秒视为同一事件)
    const auditGroups = computed(() => {
      const rows = auditDialog.rows || [];
      const order = [];      // 保持出现顺序
      const byKey = new Map();
      rows.forEach(r => {
        const key = (r.detail && r.detail.event_id) || r.event_id
                 || (r.ts + '|' + r.type);   // 兜底: 同毫秒同类合并
        if (!byKey.has(key)) {
          byKey.set(key, []);
          order.push(key);
        }
        byKey.get(key).push(r);
      });
      // 组内: human_decision 作主条目, 其余为侧面; 再按新 → 旧排序
      return order.map(k => {
        const g = byKey.get(k);
        const main = g.find(x => x.type === 'human_decision') || g[0];
        const subs = g.filter(x => x !== main);
        return { ts: main.ts, main, subs };
      }).reverse();
    });

    async function openAudit(row) {
      const assetId = row.asset_id || row.assetId || row.id;
      if (!assetId) return;
      try {
        const res = await get('/api/assets/' + encodeURIComponent(assetId) + '/audit');
        auditDialog.rows = (res.audit || []).slice();   // 旧 → 新 (分组后倒序)
        auditDialog.title = '资产留痕 — ' + (row.name || (row.namespace + '/' + row.name));
        auditDialog.show = true;
      } catch (e) { ElMessage.error('留痕加载失败: ' + e.message); }
    }
    function auditTypeOf(r) {
      return r.type === 'human_decision' ? 'primary'
           : r.type === 'status_transition' ? 'success' : 'warning';
    }
    function auditLabel(r) {
      return { auto_inference: '自动推断', human_decision: '人工决策', status_transition: '状态变迁' }[r.type] || r.type || '留痕';
    }
    function auditText(r) {
      const d = r.detail || {};
      if (r.type === 'auto_inference') {
        return [d.rule && ('规则: ' + d.rule), d.level && ('级别: ' + d.level), d.note && ('说明: ' + d.note)].filter(Boolean).join(' · ');
      }
      if (r.type === 'human_decision') {
        return [d.action && ('动作: ' + d.action), d.level && ('级别: ' + d.level), d.reason && ('原因: ' + d.reason)].filter(Boolean).join(' · ');
      }
      if (r.type === 'status_transition') {
        // 级别来源变迁 (override 产生的第二条) 不是状态变迁 — 措辞要分开
        if (d.field === 'level') {
          return '级别来源: ' + (d.from || '—') + ' → ' + (d.to || '—')
            + (d.old_level ? ' · 原级别: ' + (LEVEL_LABELS[d.old_level] || d.old_level) : '');
        }
        return '状态: ' + (d.from || '—') + ' → ' + (d.to || '—') + (d.level ? ' · 级别: ' + d.level : '');
      }
      return JSON.stringify(d);
    }
    function onQueueSelect(sel) { queueDialog.selected = sel; }
    function openQueue() { queueDialog.show = true; }
    // 方案A: 前端循环逐条 confirm (留痕按资产分条, 失败项单独汇总提示)
    async function batchTrust() {
      const sel = queueDialog.selected;
      if (!sel.length) { ElMessage.warning('请先勾选待确认资产'); return; }
      const reason = queueDialog.reason.trim();
      const ok = [];
      const fail = [];
      for (const a of sel) {
        try {
          await post('/api/assets/' + encodeURIComponent(a.assetId) + '/confirm', { reason });
          ok.push(a.name);
        } catch (e) { fail.push(a.name + ' (' + e.message + ')'); }
      }
      if (ok.length) ElMessage.success('一键信任完成: ' + ok.length + ' 项已确认' + (fail.length ? ', ' + fail.length + ' 项失败' : ''));
      if (fail.length) ElMessage.warning('失败 ' + fail.length + ' 项: ' + fail.slice(0, 3).join('; ') + (fail.length > 3 ? ' …' : ''));
      queueDialog.reason = '';
      queueDialog.show = false;
      refresh();
    }
    async function trustAll() {
      const all = pendingList.value;
      if (!all.length) { ElMessage.info('当前无待确认资产'); return; }
      try {
        await ElMessageBox.confirm('将对 ' + all.length + ' 个待确认资产执行一键信任（逐条确认并留痕，失败项单独提示）。继续？',
          '一键信任全部', { type: 'warning', confirmButtonText: '信任全部', cancelButtonText: '取消' });
      } catch (e) { return; }  // 用户取消
      queueDialog.selected = all;
      await batchTrust();
    }
    onMounted(() => {
      load();
      state.timer = setInterval(load, 5000);
      window.addEventListener('resize', () => chart && chart.resize());
    });
    onUnmounted(() => {
      clearInterval(state.timer);
      stopBlink();
      if (chart) { chart.dispose(); chart = null; }
    });
    return { data, assetDialog, openAssetDetail, showPod, topoRef, topoFilter, nsOptions,
             imageOptions,
             privateSvcOptions, buildTopoDebounced, onPrivateToggle, resetTopoFilter,
             draftFilter, filterDirty, applyFilter,
             openAsset, openOverride, openRevert,
             // v0.6.4: 资产确认闭环 (ADR-050)
             pendingList, canWrite, isAdmin, openQueue, trustAll,
             confirmDialog, openConfirm, doConfirm, doOverride,
             queueDialog, batchTrust, onQueueSelect,
             auditDialog, auditGroups, openAudit, auditTypeOf, auditLabel, auditText,
             unifiedAssets, assetCounts,
             ASSET_STATES, ASSET_STATE_TYPES, LEVEL_TYPES, LEVEL_LABELS,
             ASSET_LEVEL_OPTIONS, fmtTime, assetAge };
  },
};

/* ================================================================
 * Attack Chain (v0.5.8) — 攻击链流程图 (方框箭头, ECharts)
 * ================================================================ */
const AttackChainPage = {
  template: `
  <div v-loading="loading" element-loading-text="攻击链分析中..." style="min-height:300px">
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
            <el-tag size="small" :type="target.status === 'Running' ? 'success' : target.status === 'Succeeded' ? 'info' : target.status === 'Failed' ? 'danger' : target.status === 'Pending' ? 'warning' : 'info'">{{ target.status }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="特权">
            <el-tag size="small" :type="target.privileged ? 'danger' : 'primary'">{{ target.privileged ? '是' : '否' }}</el-tag></el-descriptions-item>
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
          <el-tag v-for="(a, ai) in alerts" :key="ai" size="small" type="warning"
                  style="margin-left:6px">{{ a.rule }} @ {{ a.ts.slice(5,19).replace('T',' ') }}</el-tag>
          <span style="margin-left:10px;font-size:12px;color:var(--muted)">仅展示最近 10 分钟行为</span>
        </h3>
        <div ref="chainRef" style="width:100%;height:300px"></div>
        <div style="margin-top:10px;font-size:12px;color:var(--muted)">
          <el-tag v-for="(c, i) in phaseColors" :key="i" size="small" style="margin-right:8px;color:#fff"
                  :color="c.color" effect="dark">{{ c.name }}</el-tag>
        </div>
      </div>
      <div class="panel">
        <h3 style="margin-bottom:10px">阶段详情</h3>
        <el-table :data="steps" size="small" stripe>
          <el-table-column label="阶段" width="110"><template #default="{row}">
            <el-tag size="small" :color="row.color" effect="dark" style="border:none;color:#fff">{{ row.phase }}</el-tag>
          </template></el-table-column>
          <el-table-column label="相对时间" width="100"><template #default="{row}">
            <span class="mono">{{ row.rel === row.end_rel ? row.rel + 's' : row.rel + 's ~ ' + row.end_rel + 's' }}</span></template></el-table-column>
          <el-table-column label="关键事件" min-width="300"><template #default="{row}">
            <div v-for="(e, ei) in row.events.slice(0,5)" :key="ei" style="font-size:12px" class="mono">
              {{ e.event_type }} {{ e.comm }} {{ e.target || '' }}<span v-if="e.count > 1" style="color:var(--warn)"> ×{{ e.count }}</span></div>
            <span v-if="row.events.length > 5" style="font-size:11px;color:var(--muted)">+{{ row.events.length - 5 }} 更多</span>
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
    const alerts = ref([]);   // 容器所有告警 (v0.5.8)
    const err = ref('');
    const target = ref(null);   // 被攻击目标画像 (v0.5.8)
    const chainRef = ref(null);
    const loading = ref(false);   // 攻击链分析 loading
    const phaseColors = [
      { name: '侦查探测', color: '#3b82f6' }, { name: '提权逃逸', color: '#ef4444' },
      { name: '利用执行', color: '#f59e0b' }, { name: '外联 C2', color: '#a855f7' },
      { name: '窃取数据', color: '#06b6d4' },
    ];
    let chart = null;

    async function load() {
      // 兼容 #/chain?container= 与 #chain?container=
      const m = location.hash.match(/\/?chain\?container=([^&]+)/);
      if (!m) { err.value = '缺少攻击链参数'; return; }
      const container = decodeURIComponent(m[1]);
      loading.value = true;
      try {
        // v0.5.8: 容器全周期 — 不传 ts, 后端取最近告警为锚点
        const d = await get('/api/attack-chain?container=' +
                            encodeURIComponent(container));
        if (d.error) { err.value = d.error; loading.value = false; return; }
        steps.value = d.steps || [];
        alerts.value = d.alerts || [];
        alert.value = { container, ts: alerts.value.length
                        ? alerts.value[alerts.value.length - 1].ts : '' };
        // v0.5.8: 被攻击目标画像
        try {
          const prof = await get('/api/review/profile?container_id=' +
                                 encodeURIComponent(container));
          target.value = prof.profile;
        } catch (e) { target.value = null; }
        // v-else 分支渲染后 chainRef 才就绪 — nextTick 再画图
        Vue.nextTick(() => renderChart());
      } catch (e) { err.value = e.message; }
      loading.value = false;
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
        const labelLines = [s.phase, timeTxt];
        if (cmd) labelLines.push(cmd);
        return {
          id: 's' + i, name: s.phase,
          symbol: 'rect',
          // v0.5.8: 阶段多时自适应 (方框变窄间距变小, 防横向溢出)
          symbolSize: [steps.value.length > 5 ? 90 : 150, 54],
          x: 10 + i * (steps.value.length > 5 ? 100 : 170), y: 40,
          itemStyle: { color: s.color, borderRadius: 4 },
          label: { show: true, color: '#fff', fontSize: steps.value.length > 5 ? 10 : 11,
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
              s.events.slice(0, 5).map(e =>
                `${e.event_type} ${e.comm} ${e.target || ''}${e.count > 1 ? ' ×' + e.count : ''}`).join('<br>') +
              (s.events.length > 5 ? '<br>+' + (s.events.length - 5) + ' 更多' : '');
          } },
        series: [{
          type: 'graph', layout: 'none', roam: 'move', draggable: false,
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
              `<div class="mono" style="font-size:12px;margin:4px 0">${e.rel}s ${e.event_type} ${e.comm} ${e.target || ''}${e.count > 1 ? ' ×' + e.count : ''}</div>`
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
    return { steps, alert, alerts, err, target, chainRef, phaseColors, loading };
  },
};

/* ================================================================
 * Rules
 * ================================================================ */
const RulesPage = {
  template: `
  <div>
    <div class="page-title">检测规则 <span class="sub">rules.yaml · guard 3s 热加载 · 可增改删</span></div>
    <div class="panel" style="display:flex;justify-content:space-between;align-items:center">
      <span style="color:var(--muted)">共 {{ rules.length }} 条规则</span>
      <el-button type="primary" size="small" @click="openAddRule">添加规则</el-button>
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
        <!-- v0.6.4: 规则编辑/删除 -->
        <el-table-column label="操作" width="150" fixed="right"><template #default="{row}">
          <el-button size="small" link type="primary" @click="openEditRule(row)">编辑</el-button>
          <el-button size="small" link type="danger" @click="removeRule(row)">删除</el-button>
        </template></el-table-column>
      </el-table>
    </div>

    <!-- 规则 编辑/添加 弹窗 -->
    <el-dialog v-model="ruleDlg.show" :title="ruleDlg.title" width="640px">
      <el-form label-width="90px" size="small">
        <el-form-item label="名称"><el-input v-model="ruleDlg.name" placeholder="suspicious_xxx" /></el-form-item>
        <el-form-item label="严重度">
          <el-select v-model="ruleDlg.severity" style="width:160px">
            <el-option v-for="s in ['CRITICAL','HIGH','MEDIUM','LOW']" :key="s" :label="s" :value="s" /></el-select>
        </el-form-item>
        <el-form-item label="事件类型">
          <el-select v-model="ruleDlg.event_type" style="width:160px">
            <el-option v-for="t in ['execve','openat','connect','mount','ptrace','capset']" :key="t" :label="t" :value="t" /></el-select>
        </el-form-item>
        <el-form-item label="攻击向量"><el-input v-model="ruleDlg.attack_vector" placeholder="custom_vector" /></el-form-item>
        <el-form-item label="描述"><el-input v-model="ruleDlg.description" /></el-form-item>
        <el-form-item label="条件 (AND)">
          <div v-for="(row, ci) in ruleDlg.condRows" :key="ci" style="display:flex;gap:8px;margin-bottom:8px;width:100%">
            <el-input v-model="row.field" placeholder="字段 (comm/target_path/uid...)" style="width:200px" />
            <el-select v-model="row.op" style="width:110px">
              <el-option v-for="op in ['==','neq','startswith','endswith','contains','glob']" :key="op" :label="op" :value="op" /></el-select>
            <el-input v-model="row.value" placeholder="值 (逗号=OR)" style="flex:1" />
            <el-button circle size="small" @click="ruleDlg.condRows.splice(ci,1)">✕</el-button>
          </div>
          <el-button size="small" @click="ruleDlg.condRows.push({field:'',op:'==',value:''})">+ 条件行</el-button>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button size="small" @click="ruleDlg.show=false">取消</el-button>
        <el-button type="primary" size="small" :loading="saving" @click="submitRule">保存 (热加载 3s 生效)</el-button>
      </template>
    </el-dialog>

    <!-- v0.6.4: 临时放行白名单 (whitelist.yaml 独立管理, 带 valid_until 时效) -->
    <div style="margin-top:18px">
      <div class="page-title" style="margin-bottom:6px">🕊️ 临时放行白名单 <span class="sub">有效期内抑制告警 · 到期自动失效 · 与规则同审计</span></div>
      <div class="panel" style="display:flex;justify-content:space-between;align-items:center">
        <span style="color:var(--muted)">共 {{ wl.length }} 条（含已到期）</span>
        <el-button type="warning" size="small" @click="openAddWhitelist">+ 新增放行</el-button>
      </div>
      <div class="panel">
        <el-table :data="wl" size="small" stripe>
          <el-table-column label="粒度" width="90"><template #default="{row}">
            <el-tag size="small" :type="row.kind === 'comm' ? 'primary' : 'success'">{{ row.kind === 'comm' ? 'comm' : '容器' }}</el-tag></template></el-table-column>
          <el-table-column label="匹配值" min-width="140"><template #default="{row}"><span class="mono">{{ row.match }}</span></template></el-table-column>
          <el-table-column label="有效至" min-width="160"><template #default="{row}">
            <span v-if="row.valid_until">{{ row.valid_until }}</span>
            <el-tag v-else size="small" type="warning">永久</el-tag></template></el-table-column>
          <el-table-column label="状态" width="90"><template #default="{row}">
            <el-tag v-if="row.active" size="small" type="success">生效中</el-tag>
            <el-tag v-else size="small" type="info">已到期</el-tag></template></el-table-column>
          <el-table-column label="理由" min-width="200"><template #default="{row}">
            <span style="font-size:12px;color:var(--muted)">{{ row.note }}</span></template></el-table-column>
          <el-table-column label="操作" width="140"><template #default="{row}">
            <el-button size="small" link type="warning" @click="extendWhitelist(row)">续期</el-button>
            <el-button size="small" link type="danger" @click="removeWhitelist(row)">删除</el-button>
          </template></el-table-column>
        </el-table>
      </div>
    </div>

    <!-- 白名单 新增/续期 弹窗 -->
    <el-dialog v-model="wlDlg.show" :title="wlDlg.title" width="560px">
      <el-form label-width="100px" size="small">
        <el-form-item label="粒度">
          <el-radio-group v-model="wlDlg.kind">
            <el-radio label="comm">按进程 comm</el-radio>
            <el-radio label="container">按容器</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="匹配值"><el-input v-model="wlDlg.match" placeholder="如 coredns / 容器 ID" /></el-form-item>
        <el-form-item label="有效时限">
          <el-radio-group v-model="wlDlg.duration">
            <el-radio label="1h">1 小时</el-radio>
            <el-radio label="24h">24 小时</el-radio>
            <el-radio label="7d">7 天</el-radio>
            <el-radio label="permanent">永久</el-radio>
            <el-radio label="custom">自定义</el-radio>
          </el-radio-group>
          <el-date-picker v-if="wlDlg.duration === 'custom'" v-model="wlDlg.until"
            type="datetime" placeholder="选择过期时间" value-format="YYYY-MM-DDTHH:mm:ss"
            style="margin-top:8px" />
        </el-form-item>
        <el-form-item label="理由"><el-input v-model="wlDlg.note" type="textarea" :rows="2" placeholder="必填 — 审计/基线学习" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button size="small" @click="wlDlg.show=false">取消</el-button>
        <el-button type="warning" size="small" :disabled="!wlDlg.note" @click="submitWhitelist">保存</el-button>
      </template>
    </el-dialog>
  </div>`,
  setup() {
    const rules = ref([]);
    const wl = ref([]);  // v0.6.4 白名单
    const saving = ref(false);
    const ruleDlg = reactive({ show: false, title: '', mode: 'add', origName: '', name: '',
      severity: 'HIGH', event_type: 'execve', attack_vector: '', description: '',
      condRows: [{ field: '', op: '==', value: '' }] });
    const wlDlg = reactive({ show: false, title: '', editId: null, kind: 'comm', match: '',
      duration: '24h', until: '', note: '' });

    async function loadRules() {
      try { rules.value = (await get('/api/rules')).rules; } catch (e) {}
    }
    async function loadWhitelist() {
      try { wl.value = (await get('/api/whitelist')).whitelist || []; } catch (e) {}
    }
    function load() { loadRules(); loadWhitelist(); }

    // ---- 规则编辑/添加 ----
    function openAddRule() {
      ruleDlg.mode = 'add'; ruleDlg.origName = ''; ruleDlg.title = '添加规则 (条件表单)';
      ruleDlg.name = ''; ruleDlg.severity = 'HIGH'; ruleDlg.event_type = 'execve';
      ruleDlg.attack_vector = ''; ruleDlg.description = '';
      ruleDlg.condRows = [{ field: '', op: '==', value: '' }];
      ruleDlg.show = true;
    }
    function openEditRule(r) {
      ruleDlg.mode = 'edit'; ruleDlg.origName = r.name; ruleDlg.title = '编辑规则 · ' + r.name;
      ruleDlg.name = r.name; ruleDlg.severity = r.severity || 'HIGH';
      ruleDlg.event_type = r.event_type || 'execve';
      ruleDlg.attack_vector = r.attack_vector || '';
      ruleDlg.description = r.description || '';
      // 简单条件 → 条件行 (仅展平第一层 AND)
      const cond = r.condition || {};
      let rows = [];
      if (Array.isArray(cond.all)) {
        rows = cond.all.map(n => {
          if (n && typeof n === 'object') {
            const [k, v] = Object.entries(n)[0] || [];
            if (v && typeof v === 'object') { const [op, vv] = Object.entries(v)[0] || []; return { field: k, op: op || '==', value: Array.isArray(vv) ? vv.join(',') : String(vv) }; }
            return { field: k, op: '==', value: Array.isArray(v) ? v.join(',') : String(v || '') };
          }
          return { field: '', op: '==', value: '' };
        }).filter(x => x.field);
      }
      ruleDlg.condRows = rows.length ? rows : [{ field: '', op: '==', value: '' }];
      ruleDlg.show = true;
    }
    async function submitRule() {
      if (!ruleDlg.name || !ruleDlg.event_type) { ElMessage.warning('名称和事件类型必填'); return; }
      const condition = { all: [] };
      ruleDlg.condRows.forEach(r => {
        if (!r.field || !r.value) return;
        const v = r.value.includes(',') ? r.value.split(',').map(s => s.trim()) : r.value.trim();
        condition.all.push(r.op === '==' ? { [r.field]: v } : { [r.field]: { [r.op]: v } });
      });
      if (condition.all.length === 0) { ElMessage.warning('至少一个条件行'); return; }
      const payload = { rule: { name: ruleDlg.name, severity: ruleDlg.severity,
        event_type: ruleDlg.event_type, attack_vector: ruleDlg.attack_vector,
        description: ruleDlg.description, condition }, source: 'manual' };
      saving.value = true;
      try {
        if (ruleDlg.mode === 'edit') {
          await fetch('/api/rules/' + encodeURIComponent(ruleDlg.origName),
            { method: 'PUT', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload), credentials: 'same-origin' })
            .then(r => { if (!r.ok) throw new Error('规则更新失败'); });
          ElMessage.success('规则已更新 (3s 内热加载)');
        } else {
          await post('/api/rules', payload);
          ElMessage.success('规则已添加 (3s 内热加载)');
        }
        ruleDlg.show = false; loadRules();
      } catch (e) { ElMessage.error(e.message || '操作失败'); }
      saving.value = false;
    }
    async function removeRule(r) {
      try {
        await ElMessageBox.confirm(`确认删除规则「${r.name}」？`, '删除规则', { type: 'warning' });
      } catch (e) { return; }
      try {
        await fetch('/api/rules/' + encodeURIComponent(r.name),
          { method: 'DELETE', credentials: 'same-origin' })
          .then(rr => { if (!rr.ok) throw new Error('规则删除失败'); });
        ElMessage.success('规则已删除 (3s 内热加载)');
        loadRules();
      } catch (e) { ElMessage.error(e.message || '删除失败'); }
    }

    // ---- 白名单 ----
    function openAddWhitelist() {
      wlDlg.editId = null; wlDlg.title = '新增临时放行';
      wlDlg.kind = 'comm'; wlDlg.match = ''; wlDlg.duration = '24h';
      wlDlg.until = ''; wlDlg.note = '';
      wlDlg.show = true;
    }
    function extendWhitelist(r) {
      wlDlg.editId = r.id; wlDlg.title = '续期白名单 · ' + r.match;
      wlDlg.kind = r.kind; wlDlg.match = r.match; wlDlg.duration = '24h';
      wlDlg.until = ''; wlDlg.note = (r.note || '') + '（续期）';
      wlDlg.show = true;
    }
    function _calcUntil(dur, custom) {
      if (dur === 'permanent') return '';
      if (dur === 'custom') return custom || '';
      const mins = { '1h': 60, '24h': 1440, '7d': 10080 }[dur] || 1440;
      const d = new Date(Date.now() + mins * 60000);
      const p = n => String(n).padStart(2, '0');
      return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
    }
    async function submitWhitelist() {
      if (!wlDlg.match || !wlDlg.note) { ElMessage.warning('匹配值和理由必填'); return; }
      const valid_until = _calcUntil(wlDlg.duration, wlDlg.until);
      try {
        if (wlDlg.editId) {
          // 续期 = 删除旧 + 新建 (保持审计清晰)
          await fetch('/api/whitelist/' + wlDlg.editId, { method: 'DELETE', credentials: 'same-origin' });
        }
        await post('/api/whitelist', { kind: wlDlg.kind, match: wlDlg.match,
          valid_until, note: wlDlg.note });
        ElMessage.success(valid_until ? `已加入白名单（至 ${valid_until}）` : '已加入永久白名单');
        wlDlg.show = false; loadWhitelist();
      } catch (e) { ElMessage.error(e.message || '白名单写入失败'); }
    }
    async function removeWhitelist(r) {
      try { await ElMessageBox.confirm(`删除白名单「${r.kind} = ${r.match}」？将立即恢复告警。`, '删除白名单', { type: 'warning' }); }
      catch (e) { return; }
      try {
        await fetch('/api/whitelist/' + r.id, { method: 'DELETE', credentials: 'same-origin' });
        ElMessage.success('白名单已删除，恢复告警'); loadWhitelist();
      } catch (e) { ElMessage.error(e.message || '删除失败'); }
    }

    usePolling(load, 3000);
    return { rules, wl, saving, ruleDlg, wlDlg, sevTag,
      openAddRule, openEditRule, submitRule, removeRule,
      openAddWhitelist, extendWhitelist, submitWhitelist, removeWhitelist };
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
        // v0.6.0: 同步左下角 AI 快捷配置
        if (window.loadAiQuick) window.loadAiQuick();
      } catch (e) { ElMessage.error(e.message); }
    }
    // v0.5.7: 激活切换
    async function activateProfile(row) {
      try {
        await post('/api/ai/activate', { name: row.name });
        ElMessage.success(`已切换到 ${row.name} (guard 3s 热加载)`);
        load();
        if (window.loadAiQuick) window.loadAiQuick();
      } catch (e) { ElMessage.error(e.message); }
    }
    async function deleteProfile(row) {
      try {
        await fetch('/api/ai/profiles/' + encodeURIComponent(row.name), { method: 'DELETE', credentials: 'same-origin' });
        ElMessage.success('配置已删除');
        load();
        if (window.loadAiQuick) window.loadAiQuick();
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
    onMounted(() => {
      load();
      window.loadSettingsData = load;  // v0.6.0: 暴露给左下角 AI 快捷切换
    });
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
                 type="primary" @click="viewChain">🔗 查看完整攻击链</el-button>
    </template>
  </el-dialog>`,
  setup() {
    // v0.5.8: 跳转攻击链页面
    function viewChain() {
      const cid = eventDetail.event.container_id;
      eventDetail.show = false;  // 跳转攻击链自动关弹窗
      // v0.5.8: 容器全周期 — 只传 container, 后端取最近告警为锚点
      location.hash = '#/chain?container=' + encodeURIComponent(cid);
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
        // v0.6.0: 同步设置页 AI 配置列表
        if (window.loadSettingsData) window.loadSettingsData();
      } catch (e) { ElMessage.error(e.message); }
      aiQuickSaving.value = false;
    }
    function toggleSidebar() {
      sidebarCollapsed.value = !sidebarCollapsed.value;
      localStorage.setItem('guard_sidebar', sidebarCollapsed.value ? '1' : '0');
    }
    // v0.5.8: 切页保持收起状态 (图标+tooltip 可导航, 不自动展开)
    function go(key) {
      location.hash = '#' + key;
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
      window.loadAiQuick = loadAiQuick;  // v0.6.0: 暴露给设置页组件
    });
    return { authed, me, route, allowedPages, currentComp, go, logout, onLoggedIn,
             themeState, setTheme, sidebarCollapsed, toggleSidebar,
             ROLE_LABELS, ROLE_COLORS, ROLE_TYPES,
             mustChangePw, pw, savingPw, submitMustChange,
             aiProfiles, aiQuick, aiQuickSaving, loadAiQuickThresholds, aiQuickSave };
  },
};

createApp(App).use(ElementPlus).mount('#app');
