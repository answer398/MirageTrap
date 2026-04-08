import { createRouter, createWebHistory } from "vue-router";
import ScreenView from "../views/ScreenView.vue";
import ConsoleView from "../views/ConsoleView.vue";
import LoginView from "../views/LoginView.vue";
import { hasAuthToken } from "../utils/authSession";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: "/",
      redirect: "/console",
    },
    {
      path: "/login",
      name: "login",
      component: LoginView,
    },
    {
      path: "/screen",
      name: "screen",
      component: ScreenView,
      meta: { requiresAuth: true },
    },
    {
      path: "/console",
      name: "console",
      component: ConsoleView,
      meta: { requiresAuth: true },
    },
  ],
});

router.beforeEach((to) => {
  const authed = hasAuthToken();
  if (to.meta.requiresAuth && !authed) {
    return {
      path: "/login",
      query: { redirect: to.fullPath },
    };
  }
  if (to.path === "/login" && authed) {
    return "/console";
  }
  return true;
});

export default router;
