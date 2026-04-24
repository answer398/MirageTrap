import { normalizeApiBase, safeStorageGet, safeStorageSet } from "./common";

const STORAGE_KEY = "miragetrap_control_planes_v1";

function createControlPlaneId(apiBase) {
  return `cp-${String(apiBase || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")}`;
}

export function deriveControlPlaneName(apiBase) {
  const normalized = normalizeApiBase(apiBase);
  if (!normalized) {
    return "控制层";
  }

  try {
    const url = new URL(normalized);
    if (["127.0.0.1", "localhost", "::1"].includes(url.hostname)) {
      return "本地控制层";
    }
    return `${url.hostname}:${url.port || (url.protocol === "https:" ? "443" : "80")}`;
  } catch (_error) {
    return normalized.replace(/^https?:\/\//, "");
  }
}

function normalizeControlPlane(raw) {
  const apiBase = normalizeApiBase(raw?.apiBase || "");
  if (!apiBase) {
    return null;
  }

  const healthStatus = String(raw?.healthStatus || "idle").trim().toLowerCase();
  const normalizedStatus = ["up", "down", "idle"].includes(healthStatus) ? healthStatus : "idle";

  return {
    id: String(raw?.id || createControlPlaneId(apiBase)),
    name: String(raw?.name || deriveControlPlaneName(apiBase)),
    apiBase,
    service: String(raw?.service || ""),
    healthStatus: normalizedStatus,
    lastCheckedAt: String(raw?.lastCheckedAt || ""),
    lastBoundAt: String(raw?.lastBoundAt || raw?.updatedAt || ""),
    lastUsedAt: String(raw?.lastUsedAt || ""),
  };
}

function saveControlPlanes(items) {
  safeStorageSet(STORAGE_KEY, JSON.stringify(items));
}

export function listControlPlanes() {
  const raw = safeStorageGet(STORAGE_KEY);
  if (!raw) {
    return [];
  }

  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }

    return parsed
      .map(normalizeControlPlane)
      .filter(Boolean)
      .sort((left, right) => {
        const leftTime = new Date(left.lastUsedAt || left.lastBoundAt || left.lastCheckedAt || 0).getTime();
        const rightTime = new Date(right.lastUsedAt || right.lastBoundAt || right.lastCheckedAt || 0).getTime();
        if (leftTime !== rightTime) {
          return rightTime - leftTime;
        }
        return left.name.localeCompare(right.name, "zh-CN");
      });
  } catch (_error) {
    return [];
  }
}

export function upsertControlPlane(item) {
  const normalized = normalizeControlPlane(item);
  if (!normalized) {
    return null;
  }

  const items = listControlPlanes();
  const nextItems = items.filter(
    (current) => current.id !== normalized.id && current.apiBase !== normalized.apiBase,
  );
  nextItems.unshift(normalized);
  saveControlPlanes(nextItems);
  return normalized;
}

export function removeControlPlaneById(id) {
  const nextItems = listControlPlanes().filter((item) => item.id !== id);
  saveControlPlanes(nextItems);
  return nextItems;
}
