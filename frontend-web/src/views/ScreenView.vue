<template>
  <div class="screen-page">
    <div class="screen-stage">
      <header class="screen-header">
        <div class="title-block">
          <p class="eyebrow">MirageTrap Situation Awareness</p>
          <h1>Web 蜜罐全球态势感知平台</h1>
          <p class="subtitle">Interactive Web Honeypot Global Situation Dashboard</p>
        </div>

        <div class="header-meta">
          <div class="meta-line">时间 {{ nowText }}</div>
          <div class="meta-line">用户 {{ username || "-" }}</div>
          <div class="meta-line">
            后端
            <span class="status-pill" :class="statusTone">{{ backendStatusText }}</span>
          </div>
          <div class="meta-line">最近同步 {{ lastSyncText }}</div>
          <div class="meta-actions">
            <button class="action-btn" type="button" @click="refreshAll">刷新</button>
            <a class="action-btn ghost" href="/console">控制台</a>
            <button class="action-btn ghost" type="button" @click="logout">退出</button>
          </div>
        </div>
      </header>

      <section class="kpi-strip">
        <article v-for="item in overviewCards" :key="item.label" class="kpi-card">
          <span>{{ item.label }}</span>
          <strong>{{ item.value }}</strong>
          <small>{{ item.note }}</small>
        </article>
      </section>

      <p v-if="errorText" class="error-banner">{{ errorText }}</p>

      <section class="battle-grid">
        <aside class="panel left-top">
          <header class="panel-head">
            <h2>请求 IP 来源</h2>
            <small>Active Sources</small>
          </header>
          <div id="source-chart" class="chart-sm"></div>
        </aside>

        <aside class="panel left-bottom">
          <header class="panel-head">
            <h2>攻击事件监测</h2>
            <small>Recent Event Stream</small>
          </header>
          <div class="event-table-shell">
            <table class="event-table">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>目标</th>
                  <th>类型</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="item in recentRows" :key="`${item.id}-${item.time}`">
                  <td>{{ item.source_ip }}</td>
                  <td>{{ shorten(item.request_preview, 28) }}</td>
                  <td>{{ typeLabel(item.event_type) }}</td>
                </tr>
                <tr v-if="recentRows.length === 0">
                  <td colspan="3" class="empty-cell">暂无数据</td>
                </tr>
              </tbody>
            </table>
          </div>
        </aside>

        <main class="panel map-panel">
          <header class="map-head">
            <div>
              <h2>全球攻击态势</h2>
              <small>Attack Lines and Hotspots</small>
            </div>
            <div class="map-legend">
              <span><i class="dot source"></i>攻击来源</span>
              <span><i class="dot home"></i>蜜罐中心</span>
            </div>
          </header>
          <div id="world-map-chart" class="world-map"></div>
          <div class="map-summary">
            <article>
              <span>热点区域</span>
              <strong>{{ fmtNum(mapSummary.region_count) }}</strong>
            </article>
            <article>
              <span>窗口攻击</span>
              <strong>{{ fmtNum(mapSummary.attack_total) }}</strong>
            </article>
            <article>
              <span>高危事件</span>
              <strong>{{ fmtNum(mapSummary.high_risk_total) }}</strong>
            </article>
          </div>
        </main>

        <aside class="panel right-top">
          <header class="panel-head">
            <h2>服务运行状态</h2>
            <small>Service Health</small>
          </header>
          <ul class="service-list">
            <li v-for="item in healthRows" :key="item.key">
              <span>{{ item.key }}</span>
              <strong :class="`tone-${item.status}`">{{ item.status }}</strong>
            </li>
          </ul>
          <div class="hotspot-block">
            <h3>来源热点</h3>
            <ul class="hotspot-list">
              <li v-for="item in hotspotRows.slice(0, 4)" :key="item.key">
                <span>{{ item.label }}</span>
                <strong>{{ fmtNum(item.attack_count) }}</strong>
              </li>
              <li v-if="hotspotRows.length === 0" class="empty-line">暂无热点数据</li>
            </ul>
          </div>
        </aside>

        <aside class="panel right-bottom">
          <header class="panel-head">
            <h2>攻击类型总览</h2>
            <small>Attack Type Overview</small>
          </header>
          <div id="attack-type-chart" class="chart-sm"></div>
        </aside>
      </section>

      <section class="panel bottom-panel">
        <header class="panel-head">
          <h2>攻击趋势统计</h2>
          <small>24 Hour Attack Flow</small>
        </header>
        <div id="trend-chart" class="trend-chart"></div>
      </section>
    </div>
  </div>
</template>

<script>
import { getDefaultApiBase, toDateTimeText, toHourText } from "../utils/common";
import { clearAuthSession, getAuthSession } from "../utils/authSession";
import { requestJson } from "../utils/apiClient";

const echarts = window.echarts;
const DEFAULT_API = getDefaultApiBase(import.meta.env.VITE_API_BASE_URL);
const DEFAULT_USERNAME = String(import.meta.env.VITE_DEFAULT_USERNAME || "admin");
const REFRESH_INTERVAL_MS = 30000;
const MAP_HOME = [121.4737, 31.2304];

const TYPE_LABELS = {
  web_req: "普通请求",
  web_sqli: "SQL 注入",
  web_xss: "XSS 注入",
  web_path_traversal: "路径遍历",
  web_cmd_exec: "命令执行",
  web_file_upload: "恶意上传",
  web_ssrf: "SSRF",
  web_ssti: "SSTI",
  web_xxe: "XXE",
  web_scan: "恶意扫描",
};

const KNOWN_COORDS = {
  china: [104.1954, 35.8617],
  cn: [104.1954, 35.8617],
  usa: [-98.5795, 39.8283],
  us: [-98.5795, 39.8283],
  "united states": [-98.5795, 39.8283],
  russia: [105.3188, 61.524],
  ru: [105.3188, 61.524],
  germany: [10.4515, 51.1657],
  france: [2.2137, 46.2276],
  japan: [138.2529, 36.2048],
  singapore: [103.8198, 1.3521],
  brazil: [-51.9253, -14.235],
  br: [-51.9253, -14.235],
  india: [78.9629, 20.5937],
  uk: [-3.436, 55.3781],
  "united kingdom": [-3.436, 55.3781],
  canada: [-106.3468, 56.1304],
  australia: [133.7751, -25.2744],
  southafrica: [22.9375, -30.5595],
  "south africa": [22.9375, -30.5595],
};

function safeNumber(value) {
  const num = Number(value || 0);
  return Number.isFinite(num) ? num : 0;
}

function hashedCoord(seed) {
  const text = String(seed || "unknown").trim().toLowerCase() || "unknown";
  let hash = 0;
  for (let index = 0; index < text.length; index += 1) {
    hash = (hash * 33 + text.charCodeAt(index)) >>> 0;
  }
  const lon = ((hash % 3600) / 10) - 180;
  const lat = (((Math.floor(hash / 3600) % 1400) / 10) - 70);
  return [Number(lon.toFixed(2)), Number(lat.toFixed(2))];
}

function resolveCoord(label) {
  const normalized = String(label || "").trim().toLowerCase();
  return KNOWN_COORDS[normalized] || hashedCoord(normalized);
}

function buildGradient(colorStart, colorEnd) {
  return new echarts.graphic.LinearGradient(0, 0, 1, 1, [
    { offset: 0, color: colorStart },
    { offset: 1, color: colorEnd },
  ]);
}

export default {
  data() {
    return {
      apiBase: "",
      token: "",
      username: "",
      nowText: "--",
      lastSyncText: "未同步",
      backendStatusText: "未连接",
      errorText: "",
      clockTimer: null,
      refreshTimer: null,

      overview: {
        today_attack_total: 0,
        active_attack_ips: 0,
        web_attack_total: 0,
        high_risk_total: 0,
        attack_type_count: 0,
      },
      topAttackers: [],
      attackTypes: [],
      trends: [],
      hotspotPoints: [],
      recentEvents: [],
      mapSummary: {
        region_count: 0,
        attack_total: 0,
        high_risk_total: 0,
      },
      healthComponents: {},
      charts: {
        sources: null,
        map: null,
        attackTypes: null,
        trends: null,
      },
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
        {
          label: "今日攻击总数",
          value: this.fmtNum(this.overview.today_attack_total),
          note: "Today attack total",
        },
        {
          label: "活跃攻击 IP",
          value: this.fmtNum(this.overview.active_attack_ips),
          note: "Unique active source IPs",
        },
        {
          label: "Web 攻击数量",
          value: this.fmtNum(this.overview.web_attack_total),
          note: "Web honeypot captured attacks",
        },
        {
          label: "攻击类型数量",
          value: this.fmtNum(this.overview.attack_type_count),
          note: `高危 ${this.fmtNum(this.overview.high_risk_total)} 条`,
        },
      ];
    },
    healthRows() {
      return Object.keys(this.healthComponents || {}).map((key) => ({
        key,
        status: String(this.healthComponents[key]?.status || "unknown"),
      }));
    },
    hotspotRows() {
      return this.hotspotPoints.map((item) => ({
        ...item,
        key: `${item.country}-${item.region}-${item.city}`,
        label: [item.country, item.region, item.city].filter(Boolean).join(" / ") || "unknown",
      }));
    },
    recentRows() {
      return (this.recentEvents || []).slice().reverse().slice(0, 12);
    },
  },
  mounted() {
    this.restoreConfig();
    this.startClock();
    window.addEventListener("resize", this.handleResize);
    this.$nextTick(() => {
      this.initCharts();
    });
    if (!this.apiBase || !this.token) {
      this.$router.replace({ path: "/login", query: { redirect: "/screen" } });
      return;
    }
    this.refreshAll();
    this.refreshTimer = window.setInterval(() => {
      this.refreshAll();
    }, REFRESH_INTERVAL_MS);
  },
  beforeUnmount() {
    if (this.clockTimer) {
      window.clearInterval(this.clockTimer);
      this.clockTimer = null;
    }
    if (this.refreshTimer) {
      window.clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
    window.removeEventListener("resize", this.handleResize);
    this.disposeCharts();
  },
  methods: {
    fmtNum(value) {
      return safeNumber(value).toLocaleString("zh-CN");
    },
    dateText(value) {
      return toDateTimeText(value);
    },
    typeLabel(value) {
      return TYPE_LABELS[String(value || "").trim().toLowerCase()] || value || "-";
    },
    shorten(text, maxLength = 24) {
      const value = String(text || "");
      return value.length > maxLength ? `${value.slice(0, maxLength)}...` : value;
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
    initCharts() {
      if (!echarts) {
        return;
      }
      this.disposeCharts();
      this.charts.sources = echarts.init(document.getElementById("source-chart"));
      this.charts.map = echarts.init(document.getElementById("world-map-chart"));
      this.charts.attackTypes = echarts.init(document.getElementById("attack-type-chart"));
      this.charts.trends = echarts.init(document.getElementById("trend-chart"));
      this.updateCharts();
    },
    disposeCharts() {
      Object.keys(this.charts).forEach((key) => {
        if (this.charts[key]) {
          this.charts[key].dispose();
          this.charts[key] = null;
        }
      });
    },
    handleResize() {
      Object.keys(this.charts).forEach((key) => {
        if (this.charts[key]) {
          this.charts[key].resize();
        }
      });
    },
    updateCharts() {
      if (!echarts) {
        return;
      }
      if (this.charts.sources) {
        this.charts.sources.setOption(this.buildSourceOption(), true);
      }
      if (this.charts.map) {
        this.charts.map.setOption(this.buildMapOption(), true);
      }
      if (this.charts.attackTypes) {
        this.charts.attackTypes.setOption(this.buildAttackTypeOption(), true);
      }
      if (this.charts.trends) {
        this.charts.trends.setOption(this.buildTrendOption(), true);
      }
    },
    buildSourceOption() {
      const items = (this.topAttackers || []).slice(0, 8).reverse();
      return {
        animationDuration: 800,
        grid: { left: 20, right: 24, top: 12, bottom: 8, containLabel: true },
        xAxis: {
          type: "value",
          axisLabel: { color: "rgba(149, 213, 255, 0.72)" },
          splitLine: { lineStyle: { color: "rgba(88, 140, 198, 0.14)" } },
        },
        yAxis: {
          type: "category",
          data: items.map((item) => item.source_ip),
          axisLabel: { color: "#cdefff", fontSize: 11 },
          axisLine: { show: false },
          axisTick: { show: false },
        },
        series: [
          {
            type: "bar",
            data: items.map((item) => safeNumber(item.attack_count)),
            barWidth: 10,
            showBackground: true,
            backgroundStyle: {
              color: "rgba(255, 255, 255, 0.05)",
              borderRadius: 8,
            },
            itemStyle: {
              borderRadius: 8,
              color: buildGradient("#29d0ff", "#1a68ff"),
              shadowBlur: 12,
              shadowColor: "rgba(41, 208, 255, 0.35)",
            },
          },
        ],
        tooltip: {
          trigger: "axis",
          axisPointer: { type: "shadow" },
          backgroundColor: "rgba(8, 22, 42, 0.95)",
          borderColor: "rgba(76, 196, 255, 0.32)",
          textStyle: { color: "#e7fbff" },
        },
      };
    },
    buildMapOption() {
      const points = (this.hotspotRows || []).slice(0, 12).map((item) => {
        const coord = resolveCoord(item.country || item.label);
        return {
          name: item.label,
          value: [...coord, safeNumber(item.attack_count)],
          attackCount: safeNumber(item.attack_count),
          uniqueIpCount: safeNumber(item.unique_ip_count),
          highRiskCount: safeNumber(item.high_risk_count),
        };
      });

      const lines = points.map((item) => ({
        fromName: item.name,
        toName: "MirageTrap",
        value: item.attackCount,
        coords: [item.value.slice(0, 2), MAP_HOME],
      }));

      return {
        animationDuration: 1200,
        geo: {
          map: "world",
          roam: false,
          zoom: 1.08,
          itemStyle: {
            areaColor: "#0c2d4d",
            borderColor: "rgba(64, 182, 255, 0.35)",
          },
          emphasis: {
            itemStyle: {
              areaColor: "#1b4a73",
            },
            label: { show: false },
          },
        },
        tooltip: {
          trigger: "item",
          backgroundColor: "rgba(8, 22, 42, 0.95)",
          borderColor: "rgba(76, 196, 255, 0.32)",
          textStyle: { color: "#e7fbff" },
          formatter(params) {
            const data = params.data || {};
            if (params.seriesType === "lines") {
              return `${data.fromName || "-"} -> ${data.toName || "-"}<br/>攻击 ${safeNumber(
                data.value,
              )} 次`;
            }
            if (Array.isArray(data.value)) {
              return `${data.name || "-"}<br/>攻击 ${safeNumber(data.attackCount)} 次<br/>来源 IP ${safeNumber(
                data.uniqueIpCount,
              )} 个<br/>高危 ${safeNumber(data.highRiskCount)} 条`;
            }
            return params.name || "-";
          },
        },
        series: [
          {
            name: "Attack Lines",
            type: "lines",
            coordinateSystem: "geo",
            zlevel: 2,
            effect: {
              show: true,
              period: 5,
              trailLength: 0.15,
              symbol: "arrow",
              symbolSize: 6,
              color: "#7fe1ff",
            },
            lineStyle: {
              width: 1.2,
              opacity: 0.55,
              curveness: 0.2,
              color: buildGradient("rgba(41, 208, 255, 0.12)", "rgba(255, 160, 92, 0.85)"),
            },
            data: lines,
          },
          {
            name: "Sources",
            type: "effectScatter",
            coordinateSystem: "geo",
            zlevel: 3,
            rippleEffect: {
              brushType: "stroke",
              scale: 4,
            },
            label: {
              show: true,
              position: "right",
              formatter: "{b}",
              color: "#d9f6ff",
              fontSize: 10,
            },
            symbolSize(value) {
              return Math.max(8, Math.min(22, 8 + safeNumber(value[2]) * 1.5));
            },
            itemStyle: {
              color: "#ffb35c",
              shadowBlur: 16,
              shadowColor: "rgba(255, 179, 92, 0.55)",
            },
            data: points,
          },
          {
            name: "Home",
            type: "effectScatter",
            coordinateSystem: "geo",
            zlevel: 4,
            rippleEffect: {
              brushType: "stroke",
              scale: 5,
            },
            symbolSize: 18,
            label: {
              show: true,
              position: "bottom",
              formatter: "MirageTrap",
              color: "#8df0ff",
              fontWeight: "bold",
            },
            itemStyle: {
              color: "#36f0ff",
              shadowBlur: 18,
              shadowColor: "rgba(54, 240, 255, 0.75)",
            },
            data: [
              {
                name: "MirageTrap",
                value: [...MAP_HOME, safeNumber(this.mapSummary.attack_total)],
              },
            ],
          },
        ],
      };
    },
    buildAttackTypeOption() {
      const items = (this.attackTypes || []).slice(0, 8);
      return {
        animationDuration: 900,
        color: [
          "#29d0ff",
          "#2d79ff",
          "#7e9bff",
          "#ffb35c",
          "#00d3a7",
          "#18a6f8",
          "#ffd166",
          "#9b8cff",
        ],
        tooltip: {
          trigger: "item",
          backgroundColor: "rgba(8, 22, 42, 0.95)",
          borderColor: "rgba(76, 196, 255, 0.32)",
          textStyle: { color: "#e7fbff" },
        },
        legend: {
          bottom: 0,
          icon: "circle",
          textStyle: {
            color: "rgba(205, 239, 255, 0.72)",
            fontSize: 10,
          },
        },
        series: [
          {
            type: "pie",
            radius: ["32%", "68%"],
            center: ["50%", "45%"],
            roseType: "radius",
            itemStyle: {
              borderRadius: 6,
              borderColor: "rgba(9, 18, 35, 0.92)",
              borderWidth: 2,
            },
            label: {
              color: "#d6f7ff",
              formatter: ({ name, value }) => `${name}\n${value}`,
              fontSize: 10,
            },
            labelLine: {
              lineStyle: { color: "rgba(205, 239, 255, 0.45)" },
            },
            data: items.map((item) => ({
              name: this.typeLabel(item.event_type),
              value: safeNumber(item.attack_count),
            })),
          },
        ],
      };
    },
    buildTrendOption() {
      const items = this.trends || [];
      return {
        animationDuration: 900,
        grid: { left: 50, right: 24, top: 20, bottom: 34 },
        tooltip: {
          trigger: "axis",
          backgroundColor: "rgba(8, 22, 42, 0.95)",
          borderColor: "rgba(76, 196, 255, 0.32)",
          textStyle: { color: "#e7fbff" },
        },
        legend: {
          right: 12,
          textStyle: { color: "rgba(205, 239, 255, 0.72)" },
        },
        xAxis: {
          type: "category",
          boundaryGap: false,
          data: items.map((item) => toHourText(item.time)),
          axisLabel: { color: "rgba(149, 213, 255, 0.72)" },
          axisLine: { lineStyle: { color: "rgba(88, 140, 198, 0.2)" } },
        },
        yAxis: {
          type: "value",
          axisLabel: { color: "rgba(149, 213, 255, 0.72)" },
          splitLine: { lineStyle: { color: "rgba(88, 140, 198, 0.14)" } },
        },
        series: [
          {
            name: "攻击总数",
            type: "line",
            smooth: true,
            symbol: "none",
            data: items.map((item) => safeNumber(item.total_attack_count)),
            lineStyle: {
              width: 3,
              color: "#2ad1ff",
            },
            areaStyle: {
              color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                { offset: 0, color: "rgba(42, 209, 255, 0.38)" },
                { offset: 1, color: "rgba(42, 209, 255, 0.02)" },
              ]),
            },
          },
          {
            name: "高危事件",
            type: "line",
            smooth: true,
            symbol: "none",
            data: items.map((item) => safeNumber(item.high_risk_count)),
            lineStyle: {
              width: 2,
              color: "#ffb35c",
            },
          },
        ],
      };
    },
    async refreshAll() {
      this.backendStatusText = "同步中";
      this.errorText = "";
      try {
        const [overview, topAttackers, attackTypes, trends, globalMap, health] = await Promise.all([
          this.request("/api/dashboard/overview"),
          this.request("/api/dashboard/top-attackers", { query: { hours: 24, limit: 8 } }),
          this.request("/api/dashboard/attack-types", { query: { hours: 24, limit: 8 } }),
          this.request("/api/dashboard/trends", { query: { hours: 24 } }),
          this.request("/api/dashboard/global-map", { query: { hours: 24, limit: 12 } }),
          this.request("/api/health/details", { withAuth: false }),
        ]);

        this.overview = overview;
        this.topAttackers = topAttackers.items || [];
        this.attackTypes = attackTypes.items || [];
        this.trends = trends.series || [];
        this.hotspotPoints = globalMap.points || [];
        this.recentEvents = globalMap.recent_events || [];
        this.mapSummary = globalMap.summary || this.mapSummary;
        this.healthComponents = health.components || {};
        this.lastSyncText = toDateTimeText(new Date().toISOString());
        this.backendStatusText = "已连接";
        this.$nextTick(() => {
          this.updateCharts();
        });
      } catch (error) {
        this.backendStatusText = "获取失败";
        this.errorText = error.message || "拉取态势数据失败";
      }
    },
    logout() {
      clearAuthSession();
      this.$router.replace({ path: "/login", query: { redirect: "/screen" } });
    },
  },
};
</script>

<style scoped>
.screen-page {
  min-height: calc(100vh - 64px);
  padding: 16px 18px 20px;
  background:
    radial-gradient(circle at 20% 18%, rgba(40, 131, 201, 0.12), transparent 22%),
    radial-gradient(circle at 82% 16%, rgba(45, 123, 255, 0.12), transparent 24%),
    radial-gradient(circle at 50% 100%, rgba(9, 119, 176, 0.18), transparent 30%),
    #0b1628;
  color: #dff9ff;
  font-family: "Rajdhani", "Noto Sans SC", sans-serif;
}

.screen-stage {
  width: min(1880px, 100%);
  margin: 0 auto;
  display: grid;
  gap: 14px;
}

.screen-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 20px;
  padding: 8px 6px 0;
}

.eyebrow {
  margin: 0;
  color: #7bd7ff;
  font-size: 12px;
  letter-spacing: 0.26em;
  text-transform: uppercase;
}

.title-block h1 {
  margin: 8px 0 0;
  font-size: clamp(30px, 3.6vw, 54px);
  line-height: 1;
  letter-spacing: 0.06em;
  color: #e8fbff;
  text-shadow: 0 0 18px rgba(84, 214, 255, 0.24);
}

.subtitle {
  margin: 10px 0 0;
  color: rgba(189, 232, 255, 0.72);
  font-size: 13px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
}

.header-meta {
  min-width: 280px;
  display: grid;
  justify-items: end;
  gap: 6px;
  padding-top: 4px;
}

.meta-line {
  color: rgba(201, 239, 255, 0.78);
  font-size: 13px;
}

.status-pill {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  margin-left: 6px;
  min-width: 56px;
  padding: 4px 10px;
  border-radius: 999px;
  border: 1px solid rgba(123, 215, 255, 0.18);
  background: rgba(14, 54, 95, 0.45);
  box-shadow: inset 0 0 12px rgba(69, 155, 219, 0.14);
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

.meta-actions {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 2px;
}

.action-btn {
  appearance: none;
  border: 1px solid rgba(100, 201, 255, 0.22);
  border-radius: 999px;
  background: linear-gradient(135deg, rgba(17, 83, 153, 0.8), rgba(14, 43, 100, 0.76));
  color: #dff9ff;
  padding: 8px 14px;
  text-decoration: none;
  cursor: pointer;
  font: inherit;
  box-shadow: inset 0 0 16px rgba(44, 149, 255, 0.18);
}

.action-btn.ghost {
  background: rgba(11, 28, 54, 0.72);
}

.kpi-strip {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}

.kpi-card,
.panel {
  position: relative;
  border: 1px solid rgba(100, 201, 255, 0.18);
  background: linear-gradient(180deg, rgba(9, 27, 52, 0.9), rgba(8, 20, 42, 0.82));
  box-shadow:
    inset 0 0 20px rgba(44, 149, 255, 0.08),
    0 16px 40px rgba(0, 0, 0, 0.2);
  overflow: hidden;
}

.kpi-card::before,
.panel::before {
  content: "";
  position: absolute;
  inset: 0;
  border: 1px solid rgba(123, 215, 255, 0.06);
  pointer-events: none;
}

.kpi-card {
  min-height: 106px;
  padding: 18px 20px;
}

.kpi-card span {
  display: block;
  color: rgba(171, 224, 255, 0.72);
  font-size: 13px;
}

.kpi-card strong {
  display: block;
  margin-top: 10px;
  font-size: 34px;
  color: #f1fdff;
  line-height: 1;
  text-shadow: 0 0 16px rgba(84, 214, 255, 0.2);
}

.kpi-card small {
  display: block;
  margin-top: 8px;
  color: rgba(132, 196, 233, 0.68);
  font-size: 11px;
  letter-spacing: 0.08em;
}

.battle-grid {
  display: grid;
  grid-template-columns: 320px minmax(0, 1fr) 320px;
  grid-template-rows: 360px 320px;
  gap: 14px;
}

.panel {
  padding: 14px 16px;
}

.panel-head,
.map-head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 12px;
  margin-bottom: 10px;
}

.panel-head h2,
.map-head h2 {
  margin: 0;
  color: #ecfbff;
  font-size: 22px;
  letter-spacing: 0.08em;
}

.panel-head small,
.map-head small {
  color: rgba(154, 219, 255, 0.62);
  font-size: 11px;
  letter-spacing: 0.18em;
  text-transform: uppercase;
}

.left-top {
  grid-column: 1;
  grid-row: 1;
}

.left-bottom {
  grid-column: 1;
  grid-row: 2;
}

.map-panel {
  grid-column: 2;
  grid-row: 1 / span 2;
  padding: 14px 18px 16px;
}

.right-top {
  grid-column: 3;
  grid-row: 1;
}

.right-bottom {
  grid-column: 3;
  grid-row: 2;
}

.chart-sm {
  height: calc(100% - 36px);
  min-height: 240px;
}

.world-map {
  height: calc(100% - 94px);
  min-height: 560px;
}

.map-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 14px;
  color: rgba(195, 236, 255, 0.74);
  font-size: 12px;
}

.dot {
  display: inline-block;
  width: 10px;
  height: 10px;
  margin-right: 6px;
  border-radius: 50%;
}

.dot.source {
  background: #ffb35c;
  box-shadow: 0 0 10px rgba(255, 179, 92, 0.65);
}

.dot.home {
  background: #36f0ff;
  box-shadow: 0 0 10px rgba(54, 240, 255, 0.7);
}

.map-summary {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
  margin-top: 10px;
}

.map-summary article {
  padding: 12px 14px;
  border: 1px solid rgba(100, 201, 255, 0.12);
  background: rgba(12, 33, 63, 0.56);
}

.map-summary span {
  display: block;
  color: rgba(171, 224, 255, 0.72);
  font-size: 12px;
}

.map-summary strong {
  display: block;
  margin-top: 6px;
  font-size: 26px;
  color: #f1fdff;
}

.event-table-shell {
  height: calc(100% - 38px);
  overflow: auto;
  scrollbar-width: thin;
}

.event-table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
  font-size: 12px;
}

.event-table th,
.event-table td {
  padding: 8px 6px;
  border-bottom: 1px solid rgba(100, 201, 255, 0.1);
  text-align: left;
  color: #cfefff;
  word-break: break-word;
}

.event-table th {
  color: rgba(171, 224, 255, 0.72);
  font-weight: 600;
}

.empty-cell,
.empty-line {
  color: rgba(171, 224, 255, 0.48);
}

.service-list,
.hotspot-list {
  list-style: none;
  padding: 0;
  margin: 0;
}

.service-list li,
.hotspot-list li {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 0;
  border-bottom: 1px solid rgba(100, 201, 255, 0.1);
  color: #dff9ff;
}

.tone-up {
  color: #6dffcb;
}

.tone-degraded {
  color: #ffd36f;
}

.tone-down {
  color: #ff957d;
}

.tone-unknown {
  color: rgba(171, 224, 255, 0.52);
}

.hotspot-block {
  margin-top: 16px;
}

.hotspot-block h3 {
  margin: 0 0 8px;
  color: #ecfbff;
  font-size: 16px;
  letter-spacing: 0.08em;
}

.bottom-panel {
  padding-bottom: 8px;
}

.trend-chart {
  height: 220px;
}

.error-banner {
  margin: 0;
  padding: 12px 14px;
  border: 1px solid rgba(255, 120, 120, 0.24);
  background: rgba(111, 24, 40, 0.46);
  color: #ffd7d7;
}

@media (max-width: 1400px) {
  .battle-grid {
    grid-template-columns: 280px minmax(0, 1fr) 280px;
  }
}

@media (max-width: 1100px) {
  .screen-page {
    padding: 12px;
  }

  .screen-header,
  .kpi-strip,
  .battle-grid {
    grid-template-columns: 1fr;
  }

  .screen-header {
    flex-direction: column;
  }

  .header-meta {
    justify-items: start;
  }

  .meta-actions {
    justify-content: flex-start;
  }

  .battle-grid {
    grid-template-rows: auto;
  }

  .left-top,
  .left-bottom,
  .map-panel,
  .right-top,
  .right-bottom {
    grid-column: auto;
    grid-row: auto;
  }

  .world-map {
    min-height: 420px;
  }

  .map-summary {
    grid-template-columns: 1fr;
  }
}
</style>
