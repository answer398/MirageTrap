<template>
  <div class="app-shell">
    <header class="global-nav">
      <RouterLink to="/screen" class="brand">
        <span>MirageTrap</span>
        <small>Web Honeypot Situation Console</small>
      </RouterLink>

      <nav class="nav-group">
        <RouterLink to="/screen" class="nav-link" :class="{ active: route.path === '/screen' }">
          大屏
        </RouterLink>
        <RouterLink to="/console" class="nav-link" :class="{ active: route.path === '/console' }">
          控制台
        </RouterLink>
        <RouterLink
          v-if="!isAuthed"
          to="/login"
          class="nav-link"
          :class="{ active: route.path === '/login' }"
        >
          登录
        </RouterLink>
      </nav>

      <div v-if="isAuthed && hasPageNavState" class="nav-status">
        <div class="nav-pill">时间 {{ pageNavState.nowText }}</div>
        <div class="nav-pill">用户 {{ pageNavState.username || "-" }}</div>
        <div class="nav-pill">
          后端
          <span class="status-pill" :class="pageStatusTone">{{ pageNavState.backendStatusText }}</span>
        </div>
        <div class="nav-pill">最近同步 {{ pageNavState.lastSyncText }}</div>
      </div>

      <div v-if="isAuthed" class="nav-actions">
        <div v-if="navControlPlaneLabel" class="nav-pill nav-pill-wide">控制层 {{ navControlPlaneLabel }}</div>
        <div v-if="!hasPageNavState && navUsername" class="nav-pill">用户 {{ navUsername }}</div>
        <button v-if="hasPageNavState" class="nav-action" type="button" @click="emitPageRefresh">
          刷新
        </button>
        <button class="nav-action ghost" type="button" @click="logout">退出</button>
      </div>
    </header>

    <main class="app-view">
      <RouterView />
    </main>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { RouterLink, RouterView, useRoute, useRouter } from "vue-router";
import { clearAuthSession, getAuthSession, hasAuthToken } from "./utils/authSession";

const route = useRoute();
const router = useRouter();

function defaultPageNavState() {
  return {
    nowText: "--",
    username: "",
    backendStatusText: "未连接",
    lastSyncText: "未同步",
  };
}

const isAuthed = ref(hasAuthToken());
const navUsername = ref(getAuthSession().username || "");
const navControlPlaneLabel = ref(getAuthSession().controlPlaneName || getAuthSession().apiBase || "");
const pageNavState = ref(defaultPageNavState());

const isScreenRoute = computed(() => route.path === "/screen");
const isConsoleRoute = computed(() => route.path === "/console");
const hasPageNavState = computed(() => isScreenRoute.value || isConsoleRoute.value);
const pageStatusTone = computed(() => {
  if (pageNavState.value.backendStatusText === "已连接") {
    return "ok";
  }
  if (pageNavState.value.backendStatusText === "同步中") {
    return "pending";
  }
  return "fail";
});

function syncAuthSessionState() {
  const session = getAuthSession();
  isAuthed.value = hasAuthToken();
  navUsername.value = session.username || "";
  navControlPlaneLabel.value = session.controlPlaneName || session.apiBase || "";
}

function resetPageNavState() {
  pageNavState.value = {
    ...defaultPageNavState(),
    username: navUsername.value || "",
  };
}

function handlePageNavState(event) {
  const payload = event?.detail || {};
  pageNavState.value = {
    ...pageNavState.value,
    ...payload,
    username: payload.username || navUsername.value || "",
  };
}

function emitPageRefresh() {
  if (isScreenRoute.value) {
    window.dispatchEvent(new CustomEvent("miragetrap:screen-refresh"));
    return;
  }
  if (isConsoleRoute.value) {
    window.dispatchEvent(new CustomEvent("miragetrap:console-refresh"));
  }
}

function logout() {
  clearAuthSession();
  syncAuthSessionState();
  resetPageNavState();
  router.replace({
    path: "/login",
    query: { redirect: route.path === "/login" ? "/screen" : route.fullPath },
  });
}

onMounted(() => {
  syncAuthSessionState();
  resetPageNavState();
  window.addEventListener("storage", syncAuthSessionState);
  window.addEventListener("miragetrap:screen-nav-state", handlePageNavState);
  window.addEventListener("miragetrap:console-nav-state", handlePageNavState);
});

onBeforeUnmount(() => {
  window.removeEventListener("storage", syncAuthSessionState);
  window.removeEventListener("miragetrap:screen-nav-state", handlePageNavState);
  window.removeEventListener("miragetrap:console-nav-state", handlePageNavState);
});

watch(
  () => route.fullPath,
  () => {
    syncAuthSessionState();
    resetPageNavState();
  },
);
</script>

<style scoped>
.app-shell {
  min-height: 100vh;
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  background: #07111f;
  overflow: hidden;
}

.app-view {
  min-height: 0;
  overflow: auto;
}

.global-nav {
  position: sticky;
  top: 0;
  z-index: 20;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 16px;
  border-bottom: 1px solid rgba(100, 201, 255, 0.16);
  background: rgba(9, 19, 38, 0.88);
  backdrop-filter: blur(10px);
  overflow-x: auto;
  white-space: nowrap;
  scrollbar-width: none;
}

.global-nav::-webkit-scrollbar {
  display: none;
}

.brand {
  display: grid;
  flex: 0 0 auto;
  text-decoration: none;
  color: #e8fbff;
}

.brand span {
  font-family: "Rajdhani", "Noto Sans SC", sans-serif;
  font-size: 20px;
  letter-spacing: 0.12em;
}

.brand small {
  color: rgba(170, 224, 255, 0.62);
  font-size: 11px;
  letter-spacing: 0.18em;
  text-transform: uppercase;
}

.nav-group,
.nav-status,
.nav-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: 0 0 auto;
  flex-wrap: nowrap;
}

.nav-group {
  margin-left: 10px;
}

.nav-status {
  margin-left: auto;
}

.nav-link,
.nav-action {
  appearance: none;
  border: 1px solid rgba(100, 201, 255, 0.18);
  border-radius: 999px;
  padding: 7px 12px;
  font-size: 12px;
  color: rgba(223, 249, 255, 0.82);
  background: rgba(10, 24, 46, 0.72);
  text-decoration: none;
  cursor: pointer;
  font: inherit;
  transition:
    transform 180ms ease,
    border-color 180ms ease,
    background 180ms ease;
}

.nav-link.active,
.nav-action:hover,
.nav-action:focus-visible,
.nav-link:hover,
.nav-link:focus-visible {
  border-color: rgba(132, 223, 255, 0.42);
  background: rgba(16, 80, 148, 0.32);
  box-shadow: inset 0 0 12px rgba(41, 208, 255, 0.12);
}

.nav-pill-wide {
  max-width: 320px;
  overflow: hidden;
  text-overflow: ellipsis;
}

.nav-action:hover,
.nav-action:focus-visible,
.nav-link:hover,
.nav-link:focus-visible {
  transform: translateY(-1px);
}

.nav-action.ghost {
  background: rgba(10, 24, 46, 0.72);
}

.nav-pill {
  display: inline-flex;
  align-items: center;
  min-height: 36px;
  padding: 0 12px;
  border-radius: 999px;
  border: 1px solid rgba(103, 200, 255, 0.16);
  background: rgba(7, 19, 36, 0.72);
  box-shadow: inset 0 0 14px rgba(45, 149, 255, 0.08);
  color: rgba(201, 239, 255, 0.8);
  font-size: 12px;
  backdrop-filter: blur(12px);
}

.status-pill {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  margin-left: 6px;
  min-width: 54px;
  padding: 3px 10px;
  border-radius: 999px;
  border: 1px solid rgba(123, 215, 255, 0.18);
  background: rgba(14, 54, 95, 0.5);
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
</style>
