<template>
  <div class="app-shell">
    <header class="global-nav">
      <RouterLink to="/screen" class="brand">
        <span>MirageTrap</span>
        <small>Web Honeypot Situation Console</small>
      </RouterLink>
      <nav class="nav-group">
        <RouterLink to="/screen" class="nav-link" :class="{ active: $route.path === '/screen' }">
          大屏
        </RouterLink>
        <RouterLink to="/console" class="nav-link" :class="{ active: $route.path === '/console' }">
          控制台
        </RouterLink>
        <RouterLink to="/login" class="nav-link" :class="{ active: $route.path === '/login' }">
          登录
        </RouterLink>
      </nav>
    </header>
    <RouterView />
  </div>
</template>

<script setup>
import { RouterLink, RouterView } from "vue-router";
</script>

<style scoped>
.global-nav {
  position: sticky;
  top: 0;
  z-index: 20;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  padding: 12px 18px;
  border-bottom: 1px solid rgba(100, 201, 255, 0.16);
  background: rgba(9, 19, 38, 0.88);
  backdrop-filter: blur(10px);
}

.brand {
  display: grid;
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

.nav-group {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.nav-link {
  text-decoration: none;
  border: 1px solid rgba(100, 201, 255, 0.16);
  border-radius: 999px;
  padding: 7px 12px;
  font-size: 12px;
  color: rgba(223, 249, 255, 0.82);
}

.nav-link.active {
  border-color: rgba(100, 201, 255, 0.32);
  background: rgba(16, 80, 148, 0.32);
  box-shadow: inset 0 0 12px rgba(41, 208, 255, 0.12);
}

@media (max-width: 720px) {
  .global-nav {
    flex-direction: column;
    align-items: stretch;
  }
}
</style>
