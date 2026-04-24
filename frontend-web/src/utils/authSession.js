import { normalizeApiBase, normalizeToken, safeStorageGet, safeStorageSet } from "./common";

const STORAGE_KEY = "miragetrap_auth_v1";

export function getAuthSession() {
  const raw = safeStorageGet(STORAGE_KEY);
  if (!raw) {
    return {
      apiBase: "",
      token: "",
      username: "",
      controlPlaneId: "",
      controlPlaneName: "",
      controlPlaneService: "",
    };
  }

  try {
    const parsed = JSON.parse(raw);
    return {
      apiBase: normalizeApiBase(parsed.apiBase || ""),
      token: normalizeToken(parsed.token || ""),
      username: String(parsed.username || ""),
      controlPlaneId: String(parsed.controlPlaneId || ""),
      controlPlaneName: String(parsed.controlPlaneName || ""),
      controlPlaneService: String(parsed.controlPlaneService || ""),
    };
  } catch (_error) {
    return {
      apiBase: "",
      token: "",
      username: "",
      controlPlaneId: "",
      controlPlaneName: "",
      controlPlaneService: "",
    };
  }
}

export function saveAuthSession({ apiBase, token, username, controlPlaneId, controlPlaneName, controlPlaneService }) {
  safeStorageSet(
    STORAGE_KEY,
    JSON.stringify({
      apiBase: normalizeApiBase(apiBase || ""),
      token: normalizeToken(token || ""),
      username: String(username || ""),
      controlPlaneId: String(controlPlaneId || ""),
      controlPlaneName: String(controlPlaneName || ""),
      controlPlaneService: String(controlPlaneService || ""),
    }),
  );
}

export function clearAuthSession() {
  safeStorageSet(STORAGE_KEY, "");
}

export function hasAuthToken() {
  const session = getAuthSession();
  return Boolean(session.apiBase && session.token);
}
