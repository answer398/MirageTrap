<template>
  <div class="login-page">
    <main class="login-card">
      <p class="eyebrow">Web Honeypot Access</p>
      <h1>MirageTrap 登录</h1>
      <p>统一登录入口，登录后可访问态势页和管理控制台。</p>

      <form class="login-form" @submit.prevent="onSubmit">
        <label>
          API Base URL
          <input v-model.trim="apiBase" type="text" placeholder="留空则使用当前前端地址代理 /api" />
          <small>建议保留默认值，让前端通过 Vite 代理访问后端，减少跨域问题。</small>
        </label>

        <label>
          用户名
          <input v-model.trim="username" type="text" placeholder="admin" />
        </label>

        <label>
          密码
          <input v-model="password" type="password" placeholder="Admin@123456" />
        </label>

        <label>
          或直接粘贴 Token
          <textarea v-model="tokenInput" rows="4" placeholder="Bearer eyJ..."></textarea>
        </label>

        <p class="message">{{ message }}</p>

        <div class="actions">
          <button class="btn secondary" type="button" @click="useProxyBase">使用当前代理地址</button>
          <button class="btn" type="submit">登录</button>
        </div>
      </form>
    </main>
  </div>
</template>

<script>
import { getDefaultApiBase, normalizeApiBase, normalizeToken } from "../utils/common";
import { saveAuthSession } from "../utils/authSession";
import { requestJson } from "../utils/apiClient";

const DEFAULT_API = getDefaultApiBase(import.meta.env.VITE_API_BASE_URL);
const DEFAULT_USERNAME = String(import.meta.env.VITE_DEFAULT_USERNAME || "admin");

export default {
  data() {
    return {
      apiBase: DEFAULT_API,
      username: DEFAULT_USERNAME,
      password: "",
      tokenInput: "",
      message: "",
    };
  },
  methods: {
    targetPath() {
      return String(this.$route.query.redirect || "/console");
    },
    useProxyBase() {
      this.apiBase = DEFAULT_API;
    },
    async onSubmit() {
      this.message = "";

      const apiBase = normalizeApiBase(this.apiBase) || DEFAULT_API;
      const username = String(this.username || "").trim();
      const password = this.password || "";
      const token = normalizeToken(this.tokenInput || "");

      if (!apiBase) {
        this.message = "API Base URL 不能为空";
        return;
      }

      if (token) {
        saveAuthSession({ apiBase, token, username });
        this.$router.replace(this.targetPath());
        return;
      }

      if (!username || !password) {
        this.message = "请填写用户名/密码，或直接填写 Token";
        return;
      }

      this.message = "登录中...";
      try {
        const formBody = new URLSearchParams();
        formBody.set("username", username);
        formBody.set("password", password);

        const data = await requestJson({
          apiBase,
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

        saveAuthSession({
          apiBase,
          token: `${tokenType} ${accessToken}`,
          username,
        });
        this.$router.replace(this.targetPath());
      } catch (error) {
        this.message = error.message || "登录失败";
      }
    },
  },
};
</script>

<style scoped>
.login-page {
  min-height: calc(100vh - 70px);
  display: grid;
  place-items: center;
  padding: 28px 18px;
  background:
    radial-gradient(circle at 18% 10%, rgba(41, 208, 255, 0.12), transparent 28%),
    radial-gradient(circle at 84% 14%, rgba(45, 123, 255, 0.14), transparent 24%),
    radial-gradient(circle at 50% 100%, rgba(9, 119, 176, 0.18), transparent 32%),
    #0b1628;
}

.login-card {
  width: min(460px, 95vw);
  position: relative;
  background: linear-gradient(180deg, rgba(9, 27, 52, 0.92), rgba(8, 20, 42, 0.86));
  border: 1px solid rgba(100, 201, 255, 0.18);
  border-radius: 24px;
  padding: 22px;
  box-shadow:
    inset 0 0 20px rgba(44, 149, 255, 0.08),
    0 26px 60px rgba(0, 0, 0, 0.28);
  color: #dff9ff;
}

.login-card::before {
  content: "";
  position: absolute;
  inset: 0;
  border-radius: inherit;
  border: 1px solid rgba(123, 215, 255, 0.05);
  pointer-events: none;
}

.eyebrow {
  margin: 0;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.2em;
  color: #7bd7ff;
}

.login-card h1 {
  margin: 8px 0 0;
  font-family: "Rajdhani", "Noto Sans SC", sans-serif;
  font-size: 34px;
  letter-spacing: 0.08em;
  color: #f1fdff;
  text-shadow: 0 0 16px rgba(84, 214, 255, 0.18);
}

.login-card p {
  margin: 6px 0 0;
  color: rgba(189, 232, 255, 0.72);
  font-size: 13px;
}

.login-form {
  margin-top: 14px;
  display: grid;
  gap: 10px;
}

.login-form label {
  display: grid;
  gap: 5px;
  font-size: 12px;
  color: rgba(171, 224, 255, 0.76);
}

.login-form small {
  color: rgba(171, 224, 255, 0.56);
}

input,
textarea {
  width: 100%;
  border: 1px solid rgba(100, 201, 255, 0.16);
  border-radius: 14px;
  background: rgba(8, 31, 58, 0.76);
  color: #dff9ff;
  padding: 10px 12px;
  font-size: 13px;
}

.message {
  margin: 0;
  min-height: 18px;
  color: #ffb35c;
  font-size: 12px;
}

.actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}

.btn {
  appearance: none;
  border: 1px solid rgba(100, 201, 255, 0.16);
  border-radius: 999px;
  background: linear-gradient(135deg, rgba(17, 83, 153, 0.8), rgba(14, 43, 100, 0.76));
  color: #dff9ff;
  padding: 9px 14px;
  cursor: pointer;
  font-size: 13px;
  box-shadow: inset 0 0 16px rgba(44, 149, 255, 0.18);
}

.btn.secondary {
  border-color: rgba(100, 201, 255, 0.16);
  background: rgba(11, 28, 54, 0.72);
  color: #dff9ff;
}
</style>
