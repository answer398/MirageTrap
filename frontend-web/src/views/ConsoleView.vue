<template>
  <div class="console-page">
    <div class="console-shell">
      <header class="console-top">
        <div class="hero-copy">
          <p class="eyebrow">Attack Management Console</p>
          <h1>Web Honey Request Review</h1>
          <p class="summary">围绕攻击事件、规则命中、单 IP 回放、证据导出与蜜罐控制进行管理。</p>
        </div>
        <div class="hero-side">
          <div class="meta-line">时间 {{ nowText }}</div>
          <div class="meta-line">用户 {{ username || "-" }}</div>
          <div class="meta-line">状态 <span class="status-pill" :class="statusTone">{{ backendStatusText }}</span></div>
          <div class="actions">
            <button class="btn" type="button" @click="refreshCurrent">刷新</button>
            <a class="btn ghost" href="/screen">态势页</a>
            <button class="btn ghost" type="button" @click="logout">退出</button>
          </div>
        </div>
      </header>

      <nav class="tab-row">
        <button
          v-for="item in tabs"
          :key="item.key"
          type="button"
          class="tab-btn"
          :class="{ active: activeTab === item.key }"
          @click="switchTab(item.key)"
        >
          {{ item.label }}
        </button>
      </nav>

      <section v-if="activeTab === 'overview'" class="panel-grid">
        <article class="card kpi-card" v-for="item in overviewCards" :key="item.label">
          <span>{{ item.label }}</span>
          <strong>{{ item.value }}</strong>
        </article>

        <article class="card wide">
          <header class="section-head">
            <h2>攻击来源排行</h2>
          </header>
          <table class="table">
            <thead>
              <tr>
                <th>IP</th>
                <th>国家</th>
                <th>次数</th>
                <th>高危</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="item in topAttackers" :key="item.source_ip">
                <td>{{ item.source_ip }}</td>
                <td>{{ item.country || "-" }}</td>
                <td>{{ fmtNum(item.attack_count) }}</td>
                <td>{{ fmtNum(item.high_risk_count) }}</td>
              </tr>
              <tr v-if="topAttackers.length === 0">
                <td colspan="4" class="empty">暂无数据</td>
              </tr>
            </tbody>
          </table>
        </article>

        <article class="card">
          <header class="section-head">
            <h2>攻击类型分布</h2>
          </header>
          <ul class="stack-list">
            <li v-for="item in attackTypes" :key="item.event_type">
              <span>{{ typeLabel(item.event_type) }}</span>
              <strong>{{ fmtNum(item.attack_count) }}</strong>
            </li>
            <li v-if="attackTypes.length === 0" class="empty-line">暂无数据</li>
          </ul>
        </article>

        <article class="card">
          <header class="section-head">
            <h2>系统健康</h2>
          </header>
          <ul class="stack-list">
            <li v-for="(item, key) in healthComponents" :key="key">
              <span>{{ key }}</span>
              <strong>{{ item.status || "unknown" }}</strong>
            </li>
          </ul>
        </article>

        <article class="card wide">
          <header class="section-head">
            <h2>最近攻击</h2>
          </header>
          <ul class="event-feed">
            <li v-for="item in recentEvents" :key="`${item.id}-${item.time}`">
              <span>{{ dateText(item.time) }}</span>
              <strong>{{ item.source_ip }}</strong>
              <em>{{ typeLabel(item.event_type) }}</em>
              <i>{{ item.request_preview }}</i>
            </li>
            <li v-if="recentEvents.length === 0" class="empty-line">暂无数据</li>
          </ul>
        </article>
      </section>

      <section v-if="activeTab === 'attacks'" class="attack-layout">
        <article class="card">
          <header class="section-head">
            <h2>攻击事件列表</h2>
            <button class="btn mini" type="button" @click="loadAttacks">查询</button>
          </header>
          <form class="filter-grid" @submit.prevent="loadAttacks">
            <label>
              来源 IP
              <input v-model.trim="attackQuery.source_ip" type="text" placeholder="198.51.100.10" />
            </label>
            <label>
              风险等级
              <select v-model="attackQuery.risk_level">
                <option value="">全部</option>
                <option value="low">low</option>
                <option value="medium">medium</option>
                <option value="high">high</option>
                <option value="critical">critical</option>
              </select>
            </label>
            <label>
              蜜罐类型
              <select v-model="attackQuery.honeypot_type">
                <option value="">全部</option>
                <option value="web">web</option>
              </select>
            </label>
          </form>
          <table class="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>时间</th>
                <th>IP</th>
                <th>路径</th>
                <th>类型</th>
                <th>规则</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="item in attacks.items"
                :key="item.id"
                class="row-link"
                :class="{ selected: selectedAttack && selectedAttack.id === item.id }"
                @click="showAttack(item.id)"
              >
                <td>{{ item.id }}</td>
                <td>{{ dateText(item.created_at) }}</td>
                <td>{{ item.source_ip }}</td>
                <td>{{ item.request_path || "/" }}</td>
                <td>{{ typeLabel(item.event_type) }}</td>
                <td>{{ (item.rule_details || []).map((rule) => rule.title).join(" / ") || "-" }}</td>
              </tr>
              <tr v-if="attacks.items.length === 0">
                <td colspan="6" class="empty">暂无数据</td>
              </tr>
            </tbody>
          </table>
        </article>

        <article class="card detail-card">
          <header class="section-head">
            <h2>攻击详情</h2>
          </header>
          <div v-if="selectedAttack" class="detail-body">
            <div class="detail-meta">
              <span>来源 {{ selectedAttack.source_ip }}</span>
              <span>时间 {{ dateText(selectedAttack.created_at) }}</span>
              <span>类型 {{ typeLabel(selectedAttack.event_type) }}</span>
              <span>风险 {{ selectedAttack.risk_level }} / {{ selectedAttack.risk_score }}</span>
            </div>
            <div class="detail-grid">
              <div>
                <h3>请求概要</h3>
                <pre>{{ jsonText({
                  method: selectedAttack.request?.method,
                  path: selectedAttack.request?.path,
                  query_string: selectedAttack.request?.query_string,
                  params: selectedAttack.request?.params,
                  headers: selectedAttack.request?.headers,
                }) }}</pre>
              </div>
              <div>
                <h3>命中规则</h3>
                <pre>{{ jsonText(selectedAttack.rule_details || []) }}</pre>
              </div>
            </div>
            <div class="detail-grid">
              <div>
                <h3>请求正文</h3>
                <pre>{{ selectedAttack.request?.body || "-" }}</pre>
              </div>
              <div>
                <h3>响应内容</h3>
                <pre>{{ selectedAttack.response?.body || "-" }}</pre>
              </div>
            </div>
            <div>
              <h3>原始请求</h3>
              <pre>{{ selectedAttack.request?.raw_request || "-" }}</pre>
            </div>
          </div>
          <div v-else class="empty-state">请选择左侧一条攻击事件查看详情。</div>
        </article>
      </section>

      <section v-if="activeTab === 'replay'" class="replay-layout">
        <article class="card">
          <header class="section-head">
            <h2>按来源 IP 回放</h2>
          </header>
          <div class="inline-form">
            <input v-model.trim="replaySourceIp" type="text" placeholder="198.51.100.10" />
            <button class="btn mini" type="button" @click="loadReplayByIp">查询</button>
          </div>
          <ul class="event-feed compact" v-if="replayByIp">
            <li v-for="item in replayByIp.timeline || []" :key="item.event_id">
              <span>{{ dateText(item.time) }}</span>
              <strong>{{ typeLabel(item.event_type) }}</strong>
              <em>{{ item.request_preview }}</em>
            </li>
          </ul>
          <div v-else class="empty-state">输入来源 IP 后查看该攻击源的时间线。</div>
        </article>

        <article class="card">
          <header class="section-head">
            <h2>按 Session 回放与导出</h2>
          </header>
          <div class="inline-form">
            <input v-model.trim="replaySessionId" type="text" placeholder="sess_xxx" />
            <button class="btn mini" type="button" @click="loadReplayTimeline">查询</button>
            <button class="btn ghost mini" type="button" @click="exportEvidence('json')" :disabled="!replaySessionId">
              导出 JSON
            </button>
            <button class="btn ghost mini" type="button" @click="exportEvidence('pcap')" :disabled="!replaySessionId">
              导出 PCAP
            </button>
          </div>
          <ul class="event-feed compact" v-if="replayTimeline">
            <li v-for="item in replayTimeline.timeline || []" :key="item.event_id">
              <span>{{ dateText(item.time) }}</span>
              <strong>{{ typeLabel(item.event_type) }}</strong>
              <em>{{ item.request_preview }}</em>
            </li>
          </ul>
          <div v-else class="empty-state">输入 Session ID 后查看时间线并导出证据。</div>
          <div v-if="evidenceData" class="evidence-panel">
            <h3>证据文件</h3>
            <ul class="stack-list">
              <li v-for="item in evidenceData.files || []" :key="item.id">
                <span>#{{ item.id }} {{ item.file_type }}</span>
                <button class="btn mini" type="button" @click="downloadFile(item.id)">
                  下载
                </button>
              </li>
            </ul>
          </div>
        </article>
      </section>

      <section v-if="activeTab === 'honeypots'" class="panel-grid honeypot-layout">
        <article class="card kpi-card" v-for="item in honeypotCards" :key="item.label">
          <span>{{ item.label }}</span>
          <strong>{{ item.value }}</strong>
        </article>

        <article class="card">
          <header class="section-head">
            <h2>新建 Web 蜜罐</h2>
            <button class="btn mini" type="button" @click="loadHoneypotCatalog">刷新镜像目录</button>
          </header>
          <form class="filter-grid honeypot-form" @submit.prevent="createHoneypot">
            <label>
              蜜罐名称
              <input v-model.trim="honeypotForm.name" type="text" placeholder="portal-decoy-01" />
            </label>
            <label>
              镜像枚举
              <select v-model="honeypotForm.image_key">
                <option v-for="item in honeypotCatalog.items" :key="item.key" :value="item.key">
                  {{ item.label }}
                </option>
              </select>
            </label>
            <label>
              映射端口
              <input v-model.number="honeypotForm.exposed_port" type="number" min="1" max="65535" />
            </label>
          </form>
          <div class="catalog-card" v-if="selectedHoneypotCatalog">
            <div class="catalog-label">{{ selectedHoneypotCatalog.label }}</div>
            <div class="catalog-meta">镜像 {{ selectedHoneypotCatalog.image_name }}</div>
            <div class="catalog-meta">诱捕模板 {{ selectedHoneypotCatalog.profile }}</div>
            <div class="catalog-meta">{{ selectedHoneypotCatalog.description }}</div>
          </div>
          <div class="actions">
            <button class="btn" type="button" @click="createHoneypot" :disabled="honeypotBusy">
              创建实例
            </button>
          </div>
        </article>

        <article class="card wide">
          <header class="section-head">
            <h2>蜜罐管理</h2>
            <button class="btn mini" type="button" @click="loadHoneypots">刷新列表</button>
          </header>
          <table class="table">
            <thead>
              <tr>
                <th>名称</th>
                <th>镜像枚举</th>
                <th>状态</th>
                <th>心跳</th>
                <th>容器</th>
                <th>地址</th>
                <th>最近上报</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="item in honeypots.items" :key="item.id">
                <td>
                  <div class="status-stack">
                    <strong>{{ item.name }}</strong>
                    <span class="muted-text">{{ item.honeypot_id }}</span>
                  </div>
                </td>
                <td>
                  <div class="status-stack">
                    <strong>{{ honeypotImageLabel(item.image_key) }}</strong>
                    <span class="muted-text">{{ item.image_name }}</span>
                  </div>
                </td>
                <td>
                  <span class="status-pill" :class="honeypotRuntimeTone(item)">{{ runtimeStatusLabel(item.runtime_status) }}</span>
                </td>
                <td>
                  <span class="status-pill" :class="honeypotHeartbeatTone(item)">{{ heartbeatStatusLabel(item.heartbeat_state) }}</span>
                </td>
                <td>
                  <div class="status-stack">
                    <strong>{{ item.container_name }}</strong>
                    <span class="muted-text">{{ item.container_id || "-" }}</span>
                  </div>
                </td>
                <td>{{ item.host_ip || "-" }}:{{ item.exposed_port || "-" }}</td>
                <td>{{ dateText(item.last_heartbeat_at) }}</td>
                <td>
                  <div class="action-cluster">
                    <button class="btn mini" type="button" @click="startHoneypot(item.id)" :disabled="honeypotBusy">
                      启动
                    </button>
                    <button class="btn ghost mini" type="button" @click="stopHoneypot(item.id)" :disabled="honeypotBusy">
                      停止
                    </button>
                    <button class="btn ghost mini" type="button" @click="deleteHoneypot(item.id)" :disabled="honeypotBusy">
                      删除
                    </button>
                  </div>
                </td>
              </tr>
              <tr v-if="honeypots.items.length === 0">
                <td colspan="8" class="empty">暂无蜜罐实例</td>
              </tr>
            </tbody>
          </table>
        </article>
      </section>
    </div>
  </div>
</template>

<script>
import { getDefaultApiBase, toDateTimeText } from "../utils/common";
import { clearAuthSession, getAuthSession } from "../utils/authSession";
import { requestBlob, requestJson } from "../utils/apiClient";

const DEFAULT_API = getDefaultApiBase(import.meta.env.VITE_API_BASE_URL);
const DEFAULT_USERNAME = String(import.meta.env.VITE_DEFAULT_USERNAME || "admin");

const TYPE_LABELS = {
  web_req: "普通请求",
  web_sqli: "SQL 注入",
  web_xss: "XSS",
  web_path_traversal: "路径遍历",
  web_cmd_exec: "命令执行",
  web_file_upload: "恶意上传",
  web_ssrf: "SSRF",
  web_ssti: "SSTI",
  web_xxe: "XXE",
  web_scan: "恶意扫描",
};

export default {
  data() {
    return {
      tabs: [
        { key: "overview", label: "态势摘要" },
        { key: "attacks", label: "攻击事件" },
        { key: "replay", label: "回放导出" },
        { key: "honeypots", label: "蜜罐管理" },
      ],
      activeTab: "overview",
      apiBase: "",
      token: "",
      username: "",
      nowText: "--",
      backendStatusText: "未连接",
      clockTimer: null,

      overview: {
        today_attack_total: 0,
        active_attack_ips: 0,
        attack_type_count: 0,
        high_risk_total: 0,
      },
      topAttackers: [],
      attackTypes: [],
      recentEvents: [],
      healthComponents: {},

      attackQuery: {
        source_ip: "",
        risk_level: "",
        honeypot_type: "web",
      },
      attacks: { items: [], total: 0, page: 1, page_size: 20 },
      selectedAttack: null,

      replaySourceIp: "",
      replaySessionId: "",
      replayByIp: null,
      replayTimeline: null,
      evidenceData: null,

      honeypotCatalog: { items: [] },
      honeypots: { items: [], total: 0, summary: {} },
      honeypotForm: {
        name: "",
        image_key: "web_portal",
        exposed_port: 18080,
      },
      honeypotBusy: false,
    };
  },
  computed: {
    statusTone() {
      if (this.backendStatusText === "已连接") {
        return "ok";
      }
      if (this.backendStatusText === "同步中") {
        return "pending";
      }
      return "fail";
    },
    overviewCards() {
      return [
        { label: "今日攻击", value: this.fmtNum(this.overview.today_attack_total) },
        { label: "活跃来源 IP", value: this.fmtNum(this.overview.active_attack_ips) },
        { label: "攻击类型数", value: this.fmtNum(this.overview.attack_type_count) },
        { label: "高危事件", value: this.fmtNum(this.overview.high_risk_total) },
      ];
    },
    selectedHoneypotCatalog() {
      return (this.honeypotCatalog.items || []).find((item) => item.key === this.honeypotForm.image_key) || null;
    },
    honeypotCards() {
      const summary = this.honeypots.summary || {};
      return [
        { label: "实例总数", value: this.fmtNum(summary.total) },
        { label: "运行中", value: this.fmtNum(summary.running) },
        { label: "心跳在线", value: this.fmtNum(summary.online) },
        { label: "心跳滞后", value: this.fmtNum(summary.stale) },
      ];
    },
  },
  mounted() {
    this.restoreConfig();
    this.startClock();
    if (!this.apiBase || !this.token) {
      this.$router.replace({ path: "/login", query: { redirect: "/console" } });
      return;
    }
    this.refreshCurrent();
  },
  beforeUnmount() {
    if (this.clockTimer) {
      window.clearInterval(this.clockTimer);
      this.clockTimer = null;
    }
  },
  methods: {
    fmtNum(value) {
      const num = Number(value || 0);
      return Number.isFinite(num) ? num.toLocaleString("zh-CN") : "0";
    },
    dateText(value) {
      return toDateTimeText(value);
    },
    jsonText(value) {
      return JSON.stringify(value || {}, null, 2);
    },
    typeLabel(value) {
      return TYPE_LABELS[String(value || "").trim().toLowerCase()] || value || "-";
    },
    restoreConfig() {
      const session = getAuthSession();
      this.apiBase = session.apiBase || DEFAULT_API;
      this.token = session.token || "";
      this.username = session.username || DEFAULT_USERNAME;
    },
    startClock() {
      const update = () => {
        this.nowText = toDateTimeText(new Date().toISOString());
      };
      update();
      this.clockTimer = window.setInterval(update, 1000);
    },
    async request(path, options = {}) {
      return requestJson({
        apiBase: this.apiBase,
        token: this.token,
        path,
        ...options,
      });
    },
    async refreshCurrent() {
      this.backendStatusText = "同步中";
      await Promise.all([this.loadOverview(), this.loadTopAttackers(), this.loadAttackTypes(), this.loadRecentEvents(), this.loadHealth()]);
      if (this.activeTab === "attacks") {
        await this.loadAttacks();
      }
      if (this.activeTab === "honeypots") {
        await Promise.all([this.loadHoneypotCatalog(), this.loadHoneypots()]);
      }
      this.backendStatusText = "已连接";
    },
    async switchTab(key) {
      this.activeTab = key;
      if (key === "attacks" && this.attacks.items.length === 0) {
        await this.loadAttacks();
      }
      if (key === "honeypots") {
        if (!this.honeypotCatalog.items.length) {
          await this.loadHoneypotCatalog();
        }
        await this.loadHoneypots();
      }
    },
    async loadOverview() {
      this.overview = await this.request("/api/dashboard/overview");
    },
    async loadTopAttackers() {
      const data = await this.request("/api/dashboard/top-attackers", { query: { hours: 24, limit: 8 } });
      this.topAttackers = data.items || [];
    },
    async loadAttackTypes() {
      const data = await this.request("/api/dashboard/attack-types", { query: { hours: 24, limit: 10 } });
      this.attackTypes = data.items || [];
    },
    async loadRecentEvents() {
      const data = await this.request("/api/dashboard/global-map", { query: { hours: 24, limit: 10 } });
      this.recentEvents = data.recent_events || [];
    },
    async loadHealth() {
      const data = await this.request("/api/health/details", { withAuth: false });
      this.healthComponents = data.components || {};
    },
    async loadAttacks() {
      this.attacks = await this.request("/api/attacks", {
        query: {
          page: 1,
          page_size: 20,
          source_ip: this.attackQuery.source_ip,
          risk_level: this.attackQuery.risk_level,
          honeypot_type: this.attackQuery.honeypot_type,
        },
      });
      if (this.attacks.items?.length && !this.selectedAttack) {
        await this.showAttack(this.attacks.items[0].id);
      }
    },
    async showAttack(eventId) {
      this.selectedAttack = await this.request(`/api/attacks/${eventId}`);
    },
    async loadReplayByIp() {
      if (!this.replaySourceIp) {
        return;
      }
      this.replayByIp = await this.request(`/api/replay/${encodeURIComponent(this.replaySourceIp)}`);
    },
    async loadReplayTimeline() {
      if (!this.replaySessionId) {
        return;
      }
      this.replayTimeline = await this.request(`/api/replay/${encodeURIComponent(this.replaySessionId)}/timeline`);
      this.evidenceData = await this.request(`/api/evidence/${encodeURIComponent(this.replaySessionId)}`);
    },
    async exportEvidence(format) {
      if (!this.replaySessionId) {
        return;
      }
      const data = await this.request(`/api/evidence/${encodeURIComponent(this.replaySessionId)}/export`, {
        method: "POST",
        query: { format },
      });
      if (data.file?.id) {
        await this.downloadFile(data.file.id);
      }
      this.evidenceData = await this.request(`/api/evidence/${encodeURIComponent(this.replaySessionId)}`);
    },
    async downloadFile(fileId) {
      const result = await requestBlob({
        apiBase: this.apiBase,
        token: this.token,
        path: `/api/files/${fileId}/download`,
      });
      const url = window.URL.createObjectURL(result.blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = this.resolveFilename(result.contentDisposition, `evidence-${fileId}`);
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);
    },
    resolveFilename(contentDisposition, fallback) {
      const match = /filename=\"?([^\";]+)\"?/i.exec(contentDisposition || "");
      return match?.[1] || fallback;
    },
    extractErrorMessage(error, fallback) {
      return error?.message || fallback;
    },
    runtimeStatusLabel(value) {
      const normalized = String(value || "").toLowerCase();
      return {
        running: "运行中",
        stopped: "已停止",
        exited: "已退出",
        missing: "容器缺失",
      }[normalized] || (value || "-");
    },
    heartbeatStatusLabel(value) {
      const normalized = String(value || "").toLowerCase();
      return {
        online: "在线",
        stale: "滞后",
        offline: "离线",
        unknown: "未知",
      }[normalized] || (value || "-");
    },
    honeypotRuntimeTone(item) {
      const status = String(item?.runtime_status || "").toLowerCase();
      if (status === "running") {
        return "ok";
      }
      if (status === "missing" || status === "exited") {
        return "pending";
      }
      return "fail";
    },
    honeypotHeartbeatTone(item) {
      const state = String(item?.heartbeat_state || "").toLowerCase();
      if (state === "online") {
        return "ok";
      }
      if (state === "stale" || state === "unknown") {
        return "pending";
      }
      return "fail";
    },
    honeypotImageLabel(key) {
      const item = (this.honeypotCatalog.items || []).find((entry) => entry.key === key);
      return item?.label || key || "-";
    },
    async loadHoneypotCatalog() {
      const data = await this.request("/api/honeypots/catalog");
      this.honeypotCatalog = data || { items: [] };
      if (!this.selectedHoneypotCatalog && this.honeypotCatalog.items?.length) {
        this.honeypotForm.image_key = this.honeypotCatalog.items[0].key;
        this.honeypotForm.exposed_port = this.honeypotCatalog.items[0].default_exposed_port || this.honeypotForm.exposed_port;
      }
    },
    async loadHoneypots() {
      this.honeypots = await this.request("/api/honeypots", {
        query: {
          page: 1,
          page_size: 20,
        },
      });
    },
    async createHoneypot() {
      if (!this.honeypotForm.name || !this.honeypotForm.image_key) {
        window.alert("请填写蜜罐名称并选择镜像枚举");
        return;
      }
      this.honeypotBusy = true;
      try {
        await this.request("/api/honeypots", {
          method: "POST",
          body: {
            name: this.honeypotForm.name,
            honeypot_type: "web",
            image_key: this.honeypotForm.image_key,
            exposed_port: this.honeypotForm.exposed_port,
          },
        });
        this.honeypotForm.name = "";
        this.honeypotForm.exposed_port = this.selectedHoneypotCatalog?.default_exposed_port || 18080;
        await this.loadHoneypots();
      } catch (error) {
        window.alert(this.extractErrorMessage(error, "创建蜜罐失败"));
      } finally {
        this.honeypotBusy = false;
      }
    },
    async startHoneypot(instanceId) {
      this.honeypotBusy = true;
      try {
        await this.request(`/api/honeypots/${instanceId}/start`, { method: "POST", body: {} });
        await this.loadHoneypots();
      } catch (error) {
        window.alert(this.extractErrorMessage(error, "启动蜜罐失败"));
      } finally {
        this.honeypotBusy = false;
      }
    },
    async stopHoneypot(instanceId) {
      this.honeypotBusy = true;
      try {
        await this.request(`/api/honeypots/${instanceId}/stop`, { method: "POST", body: {} });
        await this.loadHoneypots();
      } catch (error) {
        window.alert(this.extractErrorMessage(error, "停止蜜罐失败"));
      } finally {
        this.honeypotBusy = false;
      }
    },
    async deleteHoneypot(instanceId) {
      if (!window.confirm(`确认删除蜜罐 #${instanceId} ?`)) {
        return;
      }
      this.honeypotBusy = true;
      try {
        await this.request(`/api/honeypots/${instanceId}`, { method: "DELETE" });
        await this.loadHoneypots();
      } catch (error) {
        window.alert(this.extractErrorMessage(error, "删除蜜罐失败"));
      } finally {
        this.honeypotBusy = false;
      }
    },
    logout() {
      clearAuthSession();
      this.$router.replace({ path: "/login", query: { redirect: "/console" } });
    },
  },
};
</script>

<style scoped>
.console-page {
  min-height: calc(100vh - 64px);
  padding: 24px;
  background:
    radial-gradient(circle at 18% 14%, rgba(41, 208, 255, 0.1), transparent 24%),
    radial-gradient(circle at 84% 16%, rgba(45, 123, 255, 0.1), transparent 22%),
    radial-gradient(circle at 50% 100%, rgba(9, 119, 176, 0.16), transparent 28%),
    #0b1628;
  color: #dff9ff;
  font-family: "Rajdhani", "Noto Sans SC", sans-serif;
}

.console-shell {
  width: min(1440px, 100%);
  margin: 0 auto;
  display: grid;
  gap: 18px;
}

.console-top,
.card {
  position: relative;
  border: 1px solid rgba(100, 201, 255, 0.18);
  border-radius: 22px;
  background: linear-gradient(180deg, rgba(9, 27, 52, 0.9), rgba(8, 20, 42, 0.82));
  box-shadow:
    inset 0 0 20px rgba(44, 149, 255, 0.08),
    0 16px 40px rgba(0, 0, 0, 0.2);
}

.console-top::before,
.card::before {
  content: "";
  position: absolute;
  inset: 0;
  border-radius: inherit;
  border: 1px solid rgba(123, 215, 255, 0.05);
  pointer-events: none;
}

.console-top {
  display: flex;
  justify-content: space-between;
  gap: 18px;
  padding: 24px;
}

.eyebrow {
  margin: 0;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.22em;
  color: #7bd7ff;
}

.hero-copy h1 {
  margin: 6px 0 0;
  font-family: "Rajdhani", "Noto Sans SC", sans-serif;
  font-size: clamp(34px, 4vw, 54px);
  line-height: 0.95;
  letter-spacing: 0.06em;
  color: #f1fdff;
  text-shadow: 0 0 16px rgba(84, 214, 255, 0.18);
}

.summary {
  margin: 12px 0 0;
  max-width: 48ch;
  color: rgba(189, 232, 255, 0.72);
  line-height: 1.6;
}

.hero-side {
  min-width: 260px;
  display: grid;
  align-content: start;
  gap: 8px;
}

.meta-line {
  font-size: 13px;
  color: rgba(201, 239, 255, 0.78);
}

.status-pill {
  display: inline-block;
  padding: 4px 9px;
  border-radius: 999px;
  border: 1px solid rgba(123, 215, 255, 0.18);
  background: rgba(14, 54, 95, 0.45);
  color: #dff9ff;
}

.status-pill.ok {
  color: #6dffcb;
}

.status-pill.pending {
  color: #ffd36f;
}

.status-pill.fail {
  color: #ff957d;
}

.actions,
.tab-row,
.inline-form {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.btn,
.tab-btn {
  appearance: none;
  border: 1px solid rgba(100, 201, 255, 0.16);
  border-radius: 999px;
  padding: 10px 16px;
  cursor: pointer;
  background: linear-gradient(135deg, rgba(17, 83, 153, 0.8), rgba(14, 43, 100, 0.76));
  color: #dff9ff;
  text-decoration: none;
  font: inherit;
  box-shadow: inset 0 0 16px rgba(44, 149, 255, 0.18);
}

.btn.ghost {
  background: rgba(11, 28, 54, 0.72);
}

.btn.mini {
  padding: 8px 12px;
}

.tab-btn.active {
  border-color: rgba(100, 201, 255, 0.32);
  background: rgba(16, 80, 148, 0.32);
  color: #f1fdff;
}

.panel-grid,
.attack-layout,
.replay-layout,
.honeypot-layout {
  display: grid;
  gap: 18px;
}

.panel-grid {
  grid-template-columns: repeat(4, minmax(0, 1fr));
}

.attack-layout,
.replay-layout {
  grid-template-columns: 1.05fr 0.95fr;
}

.card {
  padding: 20px;
}

.kpi-card span {
  display: block;
  font-size: 13px;
  color: rgba(171, 224, 255, 0.72);
}

.kpi-card strong {
  display: block;
  margin-top: 8px;
  font-size: 30px;
  font-family: "Rajdhani", "Noto Sans SC", sans-serif;
  color: #f1fdff;
  text-shadow: 0 0 16px rgba(84, 214, 255, 0.2);
}

.wide {
  grid-column: span 2;
}

.section-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  margin-bottom: 14px;
}

.section-head h2,
.detail-body h3,
.evidence-panel h3 {
  margin: 0;
  color: #ecfbff;
  letter-spacing: 0.05em;
}

.table {
  width: 100%;
  border-collapse: collapse;
}

.table th,
.table td {
  padding: 11px 10px;
  border-bottom: 1px solid rgba(100, 201, 255, 0.1);
  text-align: left;
  vertical-align: top;
  font-size: 13px;
  color: #dff9ff;
}

.table th {
  color: rgba(171, 224, 255, 0.72);
}

.row-link {
  cursor: pointer;
}

.row-link.selected {
  background: rgba(16, 80, 148, 0.26);
}

.stack-list,
.event-feed {
  list-style: none;
  padding: 0;
  margin: 0;
}

.stack-list li,
.event-feed li {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  padding: 11px 0;
  border-bottom: 1px solid rgba(100, 201, 255, 0.1);
}

.event-feed li {
  display: grid;
  grid-template-columns: 168px 150px 130px 1fr;
  align-items: start;
}

.event-feed.compact li {
  grid-template-columns: 168px 120px 1fr;
}

.event-feed em,
.event-feed i {
  font-style: normal;
  color: rgba(189, 232, 255, 0.72);
}

.detail-card pre,
.detail-body pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  padding: 14px;
  border-radius: 16px;
  border: 1px solid rgba(100, 201, 255, 0.12);
  background: rgba(12, 33, 63, 0.72);
  color: #dff9ff;
  font-size: 12px;
  line-height: 1.55;
}

.detail-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 10px 18px;
  margin-bottom: 16px;
  font-size: 13px;
  color: rgba(201, 239, 255, 0.76);
}

.detail-grid,
.filter-grid {
  display: grid;
  gap: 14px;
}

.detail-grid {
  grid-template-columns: repeat(2, minmax(0, 1fr));
  margin-bottom: 14px;
}

.filter-grid {
  grid-template-columns: repeat(3, minmax(0, 1fr));
  margin-bottom: 14px;
}

.honeypot-form {
  margin-bottom: 0;
}

.catalog-card {
  margin-top: 14px;
  padding: 14px 16px;
  border-radius: 18px;
  border: 1px solid rgba(100, 201, 255, 0.12);
  background: rgba(10, 31, 59, 0.62);
  display: grid;
  gap: 6px;
}

.catalog-label {
  font-size: 16px;
  color: #f1fdff;
}

.catalog-meta,
.muted-text {
  color: rgba(189, 232, 255, 0.72);
  font-size: 12px;
}

.status-stack {
  display: grid;
  gap: 4px;
}

.action-cluster {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

label {
  display: grid;
  gap: 6px;
  font-size: 12px;
  color: rgba(171, 224, 255, 0.72);
}

input,
select {
  width: 100%;
  border: 1px solid rgba(100, 201, 255, 0.16);
  border-radius: 14px;
  padding: 11px 12px;
  background: rgba(8, 31, 58, 0.76);
  color: #dff9ff;
  font: inherit;
}

.empty,
.empty-state,
.empty-line {
  color: rgba(171, 224, 255, 0.5);
}

.evidence-panel {
  margin-top: 18px;
}

@media (max-width: 1080px) {
  .panel-grid,
  .attack-layout,
  .replay-layout,
  .detail-grid,
  .filter-grid {
    grid-template-columns: 1fr;
  }

  .wide {
    grid-column: span 1;
  }

  .console-top {
    flex-direction: column;
  }

  .event-feed li,
  .event-feed.compact li {
    grid-template-columns: 1fr;
  }
}
</style>
