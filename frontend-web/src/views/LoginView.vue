<template>
  <div class="login-page">
    <section class="login-shell">
      <aside class="login-hero">
        <p class="eyebrow">MirageTrap Control Plane</p>
        <h1>先绑定控制层，再登录</h1>
        <p class="hero-copy">
          这个前端不绑定单一机器。你可以维护多个蜜罐系统控制层，先做地址测活和绑定，再在选中的控制层上完成登录。
        </p>

        <div class="hero-points">
          <article class="hero-point">
            <span class="hero-index">01</span>
            <div>
              <strong>控制层池</strong>
              <p>把本地和远程控制层都收进同一个前端入口，后续可快速切换。</p>
            </div>
          </article>

          <article class="hero-point">
            <span class="hero-index">02</span>
            <div>
              <strong>登录前测活</strong>
              <p>先确认控制层在线，再绑定，再登录，避免把失败原因混在账号表单里。</p>
            </div>
          </article>

          <article class="hero-point">
            <span class="hero-index">03</span>
            <div>
              <strong>会话记住控制层</strong>
              <p>登录成功后，大屏与控制台都会明确知道当前连接的是哪个控制层。</p>
            </div>
          </article>
        </div>
      </aside>

      <main class="login-card">
        <section class="section-block">
          <div class="section-head">
            <span class="step-pill">STEP 1</span>
            <div>
              <h2>绑定控制层</h2>
              <p>控制层地址是蜜罐控制系统根地址，例如 `http://127.0.0.1:15000`。</p>
            </div>
          </div>

          <div class="control-plane-grid">
            <div class="draft-pane">
              <label>
                控制层名称
                <input v-model.trim="controlPlaneName" type="text" placeholder="本地控制层" />
              </label>

              <label>
                控制层地址
                <input v-model.trim="apiBase" type="text" placeholder="http://127.0.0.1:15000" />
              </label>

              <p class="field-hint">前端服务可管理多个控制层，这里填写的是当前要接入的控制层根地址。</p>
              <p v-if="pageSuggestedApiBase && pageSuggestedApiBase !== apiBase" class="field-hint">
                如果你是通过当前页面主机访问前端，可尝试填写 {{ pageSuggestedApiBase }}
              </p>

              <div class="inline-actions">
                <button class="btn secondary" type="button" :disabled="healthChecking" @click="handleCheckControlPlane">
                  {{ healthChecking ? "测活中..." : "测活控制层" }}
                </button>
                <button class="btn accent" type="button" :disabled="binding" @click="bindControlPlane">
                  {{ binding ? "绑定中..." : "绑定控制层" }}
                </button>
              </div>

              <div class="health-card" :class="healthClass">
                <div class="health-head">
                  <span class="status-dot"></span>
                  <strong>{{ health.summary }}</strong>
                </div>
                <p>{{ health.detail }}</p>
                <div class="health-meta">
                  <span>服务 {{ health.service || "--" }}</span>
                  <span>测活 {{ health.checkedAt ? dateText(health.checkedAt) : "--" }}</span>
                </div>
              </div>

              <p v-if="registryMessage" class="message" :class="registryTone">{{ registryMessage }}</p>
            </div>

            <div class="registry-pane">
              <div class="registry-head">
                <h3>已绑定控制层</h3>
                <span class="count-chip">{{ controlPlanes.length }}</span>
              </div>

              <div v-if="controlPlanes.length" class="registry-list">
                <article
                  v-for="plane in controlPlanes"
                  :key="plane.id"
                  class="plane-item"
                  :class="{ active: plane.id === selectedControlPlaneId }"
                >
                  <button class="plane-main" type="button" @click="selectControlPlane(plane.id)">
                    <div class="plane-top">
                      <strong>{{ plane.name }}</strong>
                      <span
                        class="plane-badge"
                        :class="
                          plane.healthStatus === 'up'
                            ? 'ok'
                            : plane.healthStatus === 'down'
                              ? 'fail'
                              : 'idle'
                        "
                      >
                        {{ healthLabel(plane.healthStatus) }}
                      </span>
                    </div>
                    <div class="plane-base">{{ plane.apiBase }}</div>
                    <div class="plane-meta">
                      <span>服务 {{ plane.service || "--" }}</span>
                      <span>绑定 {{ plane.lastBoundAt ? dateText(plane.lastBoundAt) : "--" }}</span>
                    </div>
                  </button>

                  <div class="plane-actions">
                    <button class="mini-btn" type="button" @click="recheckControlPlane(plane.id)">重测</button>
                    <button class="mini-btn danger" type="button" @click="removeControlPlane(plane.id)">移除</button>
                  </div>
                </article>
              </div>

              <div v-else class="empty-state">当前还没有绑定任何控制层，先完成测活并绑定。</div>
            </div>
          </div>
        </section>

        <section class="section-block auth-block">
          <div class="section-head">
            <span class="step-pill">STEP 2</span>
            <div>
              <h2>登录控制层</h2>
              <p>登录成功后，会话会绑定到当前选中的控制层。</p>
            </div>
          </div>

          <div class="selected-plane-banner" :class="{ empty: !selectedControlPlane }">
            <span class="banner-label">当前控制层</span>
            <strong>{{ selectedControlPlane ? selectedControlPlane.name : "尚未绑定控制层" }}</strong>
            <code>{{ selectedControlPlane ? selectedControlPlane.apiBase : "请先完成上方控制层绑定" }}</code>
          </div>

          <form class="login-form" @submit.prevent="onSubmit">
            <div class="login-grid">
              <label>
                用户名
                <input v-model.trim="username" type="text" placeholder="admin" autocomplete="username" />
              </label>

              <label>
                密码
                <input v-model="password" type="password" autocomplete="current-password" />
              </label>
            </div>

            <p class="message" :class="message ? 'error' : 'info'">
              {{ message || "登录后会进入当前控制层的大屏与控制台。" }}
            </p>

            <div class="actions">
              <button class="btn" type="submit" :disabled="!selectedControlPlane || loggingIn">
                {{ loggingIn ? "登录中..." : "登录控制层" }}
              </button>
            </div>
          </form>
        </section>
      </main>
    </section>
  </div>
</template>

<script>
import { requestJson } from "../utils/apiClient";
import { getAuthSession, saveAuthSession } from "../utils/authSession";
import { getDefaultApiBase, normalizeApiBase, toDateTimeText } from "../utils/common";
import {
  deriveControlPlaneName,
  listControlPlanes,
  removeControlPlaneById,
  upsertControlPlane,
} from "../utils/controlPlaneRegistry";

const DEFAULT_API = getDefaultApiBase(import.meta.env.VITE_API_BASE_URL) || "http://127.0.0.1:15000";
const DEFAULT_USERNAME = String(import.meta.env.VITE_DEFAULT_USERNAME || "admin");
const DEFAULT_CONTROL_PLANE_NAME = "本地控制层";

function createHealthState(overrides = {}) {
  return {
    status: "idle",
    service: "",
    checkedAt: "",
    summary: "尚未测活",
    detail: "先测活控制层并完成绑定，再进入登录步骤。",
    ...overrides,
  };
}

export default {
  data() {
    return {
      controlPlanes: [],
      selectedControlPlaneId: "",
      controlPlaneName: DEFAULT_CONTROL_PLANE_NAME,
      apiBase: DEFAULT_API,
      health: createHealthState(),
      healthChecking: false,
      binding: false,
      loggingIn: false,
      registryMessage: "",
      registryTone: "info",
      pageSuggestedApiBase: "",
      username: DEFAULT_USERNAME,
      password: "",
      message: "",
    };
  },
  computed: {
    selectedControlPlane() {
      return this.controlPlanes.find((item) => item.id === this.selectedControlPlaneId) || null;
    },
    healthClass() {
      return `is-${this.health.status}`;
    },
  },
  mounted() {
    this.pageSuggestedApiBase = this.resolvePageSuggestedApiBase();
    this.restoreControlPlanes();
  },
  methods: {
    targetPath() {
      return String(this.$route.query.redirect || "/console");
    },
    dateText(value) {
      return toDateTimeText(value);
    },
    healthLabel(status) {
      if (status === "up") {
        return "在线";
      }
      if (status === "down") {
        return "异常";
      }
      return "未测";
    },
    isLoopbackHost(hostname) {
      return ["127.0.0.1", "localhost", "::1"].includes(String(hostname || "").trim().toLowerCase());
    },
    resolvePageSuggestedApiBase() {
      if (typeof window === "undefined" || !window.location?.hostname) {
        return "";
      }

      const hostname = String(window.location.hostname || "").trim();
      if (!hostname) {
        return "";
      }

      const protocol = window.location.protocol || "http:";
      return normalizeApiBase(`${protocol}//${hostname}:15000`);
    },
    buildConnectivityHint(apiBase, rawMessage) {
      const fallback = rawMessage || "控制层测活失败";
      try {
        const targetUrl = new URL(apiBase);
        const currentHost = typeof window !== "undefined" ? window.location.hostname || "" : "";
        const suggestedApiBase = this.resolvePageSuggestedApiBase();

        if (this.isLoopbackHost(targetUrl.hostname)) {
          if (currentHost && !this.isLoopbackHost(currentHost) && suggestedApiBase) {
            return `当前浏览器里的 127.0.0.1 指向的是浏览器所在机器，不是控制层服务器。请改填 ${suggestedApiBase}`;
          }
          return `${fallback}。如果你是通过端口转发或本地代理打开前端，还需要把控制层 15000 一并转发到当前浏览器所在机器。`;
        }
      } catch (_error) {
        // ignore
      }
      return fallback;
    },
    async handleCheckControlPlane() {
      try {
        await this.checkControlPlane();
      } catch (_error) {
        // keep UI message only
      }
    },
    restoreControlPlanes() {
      const session = getAuthSession();
      this.controlPlanes = listControlPlanes();

      const matched =
        this.controlPlanes.find((item) => item.id === session.controlPlaneId) ||
        this.controlPlanes.find((item) => item.apiBase === session.apiBase);

      if (matched) {
        this.selectControlPlane(matched.id);
        return;
      }

      if (this.controlPlanes.length) {
        this.selectControlPlane(this.controlPlanes[0].id);
        return;
      }

      this.resetDraft();
    },
    resetDraft() {
      this.selectedControlPlaneId = "";
      this.controlPlaneName = DEFAULT_CONTROL_PLANE_NAME;
      this.apiBase = DEFAULT_API;
      this.health = createHealthState();
    },
    applyPlaneToDraft(plane) {
      this.controlPlaneName = plane.name || deriveControlPlaneName(plane.apiBase);
      this.apiBase = plane.apiBase || DEFAULT_API;
      this.health = createHealthState({
        status: plane.healthStatus || "idle",
        service: plane.service || "",
        checkedAt: plane.lastCheckedAt || "",
        summary:
          plane.healthStatus === "up"
            ? "控制层在线"
            : plane.healthStatus === "down"
              ? "上次测活失败"
              : "尚未测活",
        detail: plane.apiBase || "请选择控制层",
      });
    },
    selectControlPlane(id) {
      const plane = this.controlPlanes.find((item) => item.id === id);
      if (!plane) {
        return;
      }
      this.selectedControlPlaneId = plane.id;
      this.applyPlaneToDraft(plane);
      this.registryMessage = `已选择 ${plane.name}`;
      this.registryTone = "info";
      this.message = "";
    },
    resolveControlPlaneName(apiBase) {
      const customName = String(this.controlPlaneName || "").trim();
      return customName || deriveControlPlaneName(apiBase);
    },
    async checkControlPlane({ silent = false } = {}) {
      const apiBase = normalizeApiBase(this.apiBase);
      if (!apiBase) {
        const error = new Error("控制层地址不能为空");
        this.health = createHealthState({
          status: "down",
          checkedAt: new Date().toISOString(),
          summary: "控制层地址无效",
          detail: error.message,
        });
        if (!silent) {
          this.registryMessage = error.message;
          this.registryTone = "error";
        }
        throw error;
      }

      this.healthChecking = true;
      try {
        const data = await requestJson({
          apiBase,
          token: "",
          path: "/api/health",
          withAuth: false,
        });
        const checkedAt = new Date().toISOString();
        this.health = createHealthState({
          status: "up",
          service: String(data.service || ""),
          checkedAt,
          summary: "控制层在线，可绑定",
          detail: `${apiBase} 已响应测活请求`,
        });
        if (!silent) {
          this.registryMessage = "控制层测活成功";
          this.registryTone = "success";
        }
        return {
          apiBase,
          service: String(data.service || ""),
          lastCheckedAt: checkedAt,
          healthStatus: "up",
        };
      } catch (error) {
        const detail = this.buildConnectivityHint(apiBase, error.message || "控制层测活失败");
        const checkedAt = new Date().toISOString();
        this.health = createHealthState({
          status: "down",
          checkedAt,
          summary: "控制层不可用",
          detail,
        });
        if (!silent) {
          this.registryMessage = this.health.detail;
          this.registryTone = "error";
        }
        throw new Error(detail);
      } finally {
        this.healthChecking = false;
      }
    },
    async bindControlPlane() {
      this.registryMessage = "";
      this.message = "";
      this.binding = true;

      try {
        const healthInfo = await this.checkControlPlane({ silent: true });
        const now = new Date().toISOString();
        const current = this.selectedControlPlane;
        const saved = upsertControlPlane({
          id: current?.apiBase === healthInfo.apiBase ? current.id : "",
          name: this.resolveControlPlaneName(healthInfo.apiBase),
          apiBase: healthInfo.apiBase,
          service: healthInfo.service,
          healthStatus: healthInfo.healthStatus,
          lastCheckedAt: healthInfo.lastCheckedAt,
          lastBoundAt: now,
          lastUsedAt: current?.lastUsedAt || "",
        });

        this.controlPlanes = listControlPlanes();
        if (saved?.id) {
          this.selectControlPlane(saved.id);
        }
        this.registryMessage = `已绑定 ${saved?.name || "控制层"}`;
        this.registryTone = "success";
      } catch (error) {
        this.registryMessage = error.message || "绑定控制层失败";
        this.registryTone = "error";
      } finally {
        this.binding = false;
      }
    },
    async recheckControlPlane(id) {
      const plane = this.controlPlanes.find((item) => item.id === id);
      if (!plane) {
        return;
      }

      this.selectedControlPlaneId = plane.id;
      this.applyPlaneToDraft(plane);

      try {
        const healthInfo = await this.checkControlPlane({ silent: true });
        const saved = upsertControlPlane({
          ...plane,
          service: healthInfo.service,
          healthStatus: healthInfo.healthStatus,
          lastCheckedAt: healthInfo.lastCheckedAt,
        });
        this.controlPlanes = listControlPlanes();
        if (saved?.id) {
          this.selectControlPlane(saved.id);
        }
        this.registryMessage = `${plane.name} 测活成功`;
        this.registryTone = "success";
      } catch (error) {
        const saved = upsertControlPlane({
          ...plane,
          healthStatus: "down",
          lastCheckedAt: new Date().toISOString(),
        });
        this.controlPlanes = listControlPlanes();
        if (saved?.id) {
          this.selectControlPlane(saved.id);
        }
        this.registryMessage = error.message || "控制层测活失败";
        this.registryTone = "error";
      }
    },
    removeControlPlane(id) {
      const nextItems = removeControlPlaneById(id);
      this.controlPlanes = nextItems;

      if (this.selectedControlPlaneId === id) {
        if (nextItems.length) {
          this.selectControlPlane(nextItems[0].id);
        } else {
          this.resetDraft();
        }
      }

      this.registryMessage = "已移除控制层";
      this.registryTone = "info";
      this.message = "";
    },
    async onSubmit() {
      this.message = "";

      const plane = this.selectedControlPlane;
      const username = String(this.username || "").trim();
      const password = this.password || "";

      if (!plane) {
        this.message = "请先测活并绑定控制层";
        return;
      }

      if (!username || !password) {
        this.message = "请填写用户名和密码";
        return;
      }

      this.loggingIn = true;
      try {
        const formBody = new URLSearchParams();
        formBody.set("username", username);
        formBody.set("password", password);

        const data = await requestJson({
          apiBase: plane.apiBase,
          token: "",
          path: "/api/auth/login",
          method: "POST",
          withAuth: false,
          rawBody: formBody.toString(),
          contentType: "application/x-www-form-urlencoded;charset=UTF-8",
        });

        const tokenType = String(data.token_type || "Bearer").trim();
        const accessToken = String(data.access_token || "").trim();
        if (!accessToken) {
          throw new Error("登录成功但未返回 access_token");
        }

        const savedPlane = upsertControlPlane({
          ...plane,
          name: plane.name || deriveControlPlaneName(plane.apiBase),
          healthStatus: "up",
          lastCheckedAt: plane.lastCheckedAt || new Date().toISOString(),
          lastBoundAt: plane.lastBoundAt || new Date().toISOString(),
          lastUsedAt: new Date().toISOString(),
        });
        this.controlPlanes = listControlPlanes();
        this.selectedControlPlaneId = savedPlane?.id || plane.id;

        saveAuthSession({
          apiBase: plane.apiBase,
          token: `${tokenType} ${accessToken}`,
          username,
          controlPlaneId: savedPlane?.id || plane.id,
          controlPlaneName: savedPlane?.name || plane.name,
          controlPlaneService: savedPlane?.service || plane.service || "",
        });
        this.$router.replace(this.targetPath());
      } catch (error) {
        this.message = error.message || "登录失败";
      } finally {
        this.loggingIn = false;
      }
    },
  },
};
</script>

<style scoped>
.login-page {
  min-height: calc(100vh - 70px);
  padding: 26px 18px;
  background:
    radial-gradient(circle at 16% 10%, rgba(41, 208, 255, 0.12), transparent 28%),
    radial-gradient(circle at 82% 14%, rgba(45, 123, 255, 0.12), transparent 24%),
    radial-gradient(circle at 50% 100%, rgba(9, 119, 176, 0.16), transparent 32%),
    #081321;
}

.login-shell {
  width: min(1320px, 100%);
  margin: 0 auto;
  display: grid;
  grid-template-columns: minmax(280px, 0.82fr) minmax(0, 1.18fr);
  gap: 18px;
  align-items: stretch;
}

.login-hero,
.login-card {
  position: relative;
  border: 1px solid rgba(100, 201, 255, 0.16);
  border-radius: 28px;
  background: linear-gradient(180deg, rgba(8, 24, 46, 0.94), rgba(7, 18, 35, 0.9));
  box-shadow:
    inset 0 0 22px rgba(44, 149, 255, 0.08),
    0 28px 64px rgba(0, 0, 0, 0.26);
  color: #dff9ff;
}

.login-hero::before,
.login-card::before {
  content: "";
  position: absolute;
  inset: 0;
  border-radius: inherit;
  border: 1px solid rgba(123, 215, 255, 0.04);
  pointer-events: none;
}

.login-hero {
  padding: 24px;
  display: grid;
  gap: 18px;
  align-content: start;
}

.eyebrow {
  margin: 0;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.2em;
  color: #7bd7ff;
}

.login-hero h1 {
  margin: 0;
  font-family: "Rajdhani", "Noto Sans SC", sans-serif;
  font-size: clamp(32px, 4vw, 48px);
  line-height: 1.04;
  letter-spacing: 0.06em;
  color: #f1fdff;
  text-shadow: 0 0 16px rgba(84, 214, 255, 0.16);
}

.hero-copy {
  margin: 0;
  color: rgba(189, 232, 255, 0.78);
  font-size: 14px;
  line-height: 1.8;
}

.hero-points {
  display: grid;
  gap: 12px;
}

.hero-point {
  display: grid;
  grid-template-columns: 54px minmax(0, 1fr);
  gap: 12px;
  padding: 14px 16px;
  border-radius: 18px;
  border: 1px solid rgba(100, 201, 255, 0.1);
  background: rgba(8, 30, 57, 0.68);
}

.hero-index {
  display: grid;
  place-items: center;
  border-radius: 14px;
  background: rgba(11, 65, 115, 0.44);
  color: #7bd7ff;
  font-family: "Rajdhani", "Noto Sans SC", sans-serif;
  font-size: 20px;
  letter-spacing: 0.08em;
}

.hero-point strong {
  display: block;
  margin: 0;
  font-size: 15px;
  color: #f1fdff;
}

.hero-point p {
  margin: 6px 0 0;
  color: rgba(189, 232, 255, 0.72);
  font-size: 13px;
  line-height: 1.7;
}

.login-card {
  padding: 22px;
  display: grid;
  gap: 18px;
}

.section-block {
  display: grid;
  gap: 16px;
  padding: 18px;
  border-radius: 22px;
  border: 1px solid rgba(100, 201, 255, 0.12);
  background: rgba(6, 21, 41, 0.56);
}

.section-head {
  display: flex;
  align-items: flex-start;
  gap: 14px;
}

.section-head h2 {
  margin: 0;
  font-size: 22px;
  color: #f1fdff;
  letter-spacing: 0.04em;
}

.section-head p {
  margin: 6px 0 0;
  color: rgba(189, 232, 255, 0.68);
  font-size: 13px;
}

.step-pill {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 78px;
  min-height: 30px;
  padding: 0 12px;
  border-radius: 999px;
  border: 1px solid rgba(123, 215, 255, 0.2);
  background: rgba(13, 45, 79, 0.56);
  color: #7bd7ff;
  font-size: 11px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
}

.control-plane-grid {
  display: grid;
  grid-template-columns: minmax(0, 0.98fr) minmax(0, 1.02fr);
  gap: 16px;
}

.draft-pane,
.registry-pane {
  display: grid;
  gap: 12px;
  min-height: 0;
}

label {
  display: grid;
  gap: 6px;
  color: rgba(171, 224, 255, 0.8);
  font-size: 12px;
}

input {
  width: 100%;
  border: 1px solid rgba(100, 201, 255, 0.14);
  border-radius: 14px;
  background: rgba(8, 31, 58, 0.76);
  color: #dff9ff;
  padding: 11px 12px;
  font-size: 13px;
}

.field-hint {
  margin: -2px 0 0;
  color: rgba(171, 224, 255, 0.56);
  font-size: 12px;
  line-height: 1.7;
}

.inline-actions,
.actions,
.plane-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.actions {
  justify-content: flex-end;
}

.btn,
.mini-btn,
.plane-main {
  appearance: none;
  font: inherit;
}

.btn {
  border: 1px solid rgba(100, 201, 255, 0.18);
  border-radius: 999px;
  background: linear-gradient(135deg, rgba(18, 90, 160, 0.82), rgba(14, 43, 100, 0.76));
  color: #dff9ff;
  padding: 10px 16px;
  cursor: pointer;
  font-size: 13px;
  box-shadow: inset 0 0 16px rgba(44, 149, 255, 0.16);
}

.btn.secondary,
.mini-btn {
  background: rgba(10, 26, 48, 0.8);
}

.btn.accent {
  background: linear-gradient(135deg, rgba(24, 122, 114, 0.92), rgba(12, 72, 82, 0.82));
}

.btn:disabled,
.mini-btn:disabled {
  opacity: 0.58;
  cursor: not-allowed;
}

.health-card {
  padding: 14px 15px;
  border-radius: 18px;
  border: 1px solid rgba(100, 201, 255, 0.12);
  background: rgba(9, 28, 51, 0.72);
}

.health-card.is-up {
  border-color: rgba(64, 220, 181, 0.28);
  box-shadow: inset 0 0 22px rgba(35, 176, 140, 0.08);
}

.health-card.is-down {
  border-color: rgba(255, 108, 86, 0.28);
  box-shadow: inset 0 0 22px rgba(255, 108, 86, 0.08);
}

.health-head {
  display: flex;
  align-items: center;
  gap: 10px;
}

.status-dot {
  width: 10px;
  height: 10px;
  border-radius: 999px;
  background: #7d9db5;
  box-shadow: 0 0 12px rgba(125, 157, 181, 0.36);
}

.health-card.is-up .status-dot {
  background: #40dcb5;
  box-shadow: 0 0 12px rgba(64, 220, 181, 0.46);
}

.health-card.is-down .status-dot {
  background: #ff6c56;
  box-shadow: 0 0 12px rgba(255, 108, 86, 0.46);
}

.health-card p {
  margin: 8px 0 0;
  color: rgba(189, 232, 255, 0.72);
  font-size: 13px;
  line-height: 1.7;
}

.health-meta,
.plane-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-top: 10px;
  color: rgba(171, 224, 255, 0.56);
  font-size: 12px;
}

.registry-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.registry-head h3 {
  margin: 0;
  color: #f1fdff;
  font-size: 15px;
  letter-spacing: 0.05em;
}

.count-chip {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 28px;
  height: 28px;
  padding: 0 8px;
  border-radius: 999px;
  background: rgba(11, 65, 115, 0.42);
  color: #7bd7ff;
  font-size: 12px;
}

.registry-list {
  display: grid;
  gap: 10px;
  max-height: 360px;
  overflow: auto;
  padding-right: 4px;
}

.plane-item {
  display: grid;
  gap: 8px;
  padding: 12px;
  border-radius: 18px;
  border: 1px solid rgba(100, 201, 255, 0.1);
  background: rgba(8, 28, 52, 0.68);
}

.plane-item.active {
  border-color: rgba(123, 215, 255, 0.32);
  box-shadow: inset 0 0 18px rgba(44, 149, 255, 0.12);
}

.plane-main {
  width: 100%;
  display: grid;
  gap: 8px;
  padding: 0;
  background: transparent;
  border: none;
  color: inherit;
  text-align: left;
  cursor: pointer;
}

.plane-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.plane-top strong {
  color: #f1fdff;
  font-size: 14px;
}

.plane-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 48px;
  height: 24px;
  padding: 0 8px;
  border-radius: 999px;
  font-size: 11px;
  letter-spacing: 0.08em;
}

.plane-badge.ok {
  background: rgba(44, 196, 152, 0.16);
  color: #58e1c1;
}

.plane-badge.fail {
  background: rgba(255, 108, 86, 0.16);
  color: #ff907d;
}

.plane-badge.idle {
  background: rgba(125, 157, 181, 0.14);
  color: #a5c0d5;
}

.plane-base,
.selected-plane-banner code {
  font-family: "Fira Code", "Consolas", monospace;
  font-size: 12px;
  color: #9cdfff;
  word-break: break-all;
}

.mini-btn {
  border: 1px solid rgba(100, 201, 255, 0.14);
  border-radius: 12px;
  color: #dff9ff;
  padding: 6px 10px;
  cursor: pointer;
}

.mini-btn.danger {
  border-color: rgba(255, 108, 86, 0.2);
  color: #ff9b8b;
}

.empty-state {
  min-height: 148px;
  display: grid;
  place-items: center;
  padding: 18px;
  border: 1px dashed rgba(100, 201, 255, 0.14);
  border-radius: 18px;
  color: rgba(171, 224, 255, 0.56);
  font-size: 13px;
  text-align: center;
}

.selected-plane-banner {
  display: grid;
  gap: 6px;
  padding: 14px 16px;
  border-radius: 18px;
  border: 1px solid rgba(100, 201, 255, 0.14);
  background: rgba(8, 31, 58, 0.7);
}

.selected-plane-banner.empty {
  border-style: dashed;
  color: rgba(171, 224, 255, 0.56);
}

.banner-label {
  color: rgba(171, 224, 255, 0.6);
  font-size: 11px;
  letter-spacing: 0.14em;
  text-transform: uppercase;
}

.selected-plane-banner strong {
  color: #f1fdff;
  font-size: 15px;
}

.login-form,
.auth-block,
.login-grid {
  display: grid;
  gap: 12px;
}

.login-grid {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.message {
  margin: 0;
  min-height: 18px;
  font-size: 12px;
}

.message.info {
  color: rgba(171, 224, 255, 0.62);
}

.message.success {
  color: #58e1c1;
}

.message.error {
  color: #ffb35c;
}

@media (max-width: 1080px) {
  .login-shell,
  .control-plane-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 720px) {
  .login-page {
    padding: 18px 12px;
  }

  .login-card,
  .login-hero {
    padding: 18px;
  }

  .section-block {
    padding: 15px;
  }

  .section-head,
  .plane-top,
  .health-meta,
  .plane-meta,
  .inline-actions,
  .actions,
  .plane-actions {
    flex-direction: column;
    align-items: stretch;
  }

  .login-grid,
  .hero-point {
    grid-template-columns: 1fr;
  }
}
</style>
