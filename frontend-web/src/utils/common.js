export function normalizeApiBase(input) {
  const raw = String(input || "").trim();
  if (!raw) {
    return "";
  }

  let value = raw.replace(/\/+$/, "");
  value = value.replace(/\/api$/i, "");
  if (!/^https?:\/\//i.test(value)) {
    value = `http://${value}`;
  }
  return value;
}

export function getDefaultApiBase(configured) {
  const configuredBase = normalizeApiBase(configured || "");
  if (configuredBase) {
    return configuredBase;
  }

  return "http://127.0.0.1:15000";
}

export function normalizeToken(input) {
  const raw = String(input || "").trim();
  if (!raw) {
    return "";
  }

  if (/^bearer\s+/i.test(raw)) {
    return `Bearer ${raw.replace(/^bearer\s+/i, "").trim()}`;
  }
  return `Bearer ${raw}`;
}

export function stripBearer(input) {
  return String(input || "").replace(/^bearer\s+/i, "").trim();
}

export function safeStorageGet(key) {
  try {
    return window.localStorage.getItem(key);
  } catch (_error) {
    return null;
  }
}

export function safeStorageSet(key, value) {
  try {
    window.localStorage.setItem(key, value);
  } catch (_error) {
    // ignore
  }
}

export function toDateTimeText(value) {
  if (!value) {
    return "--";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }
  const pad = (num) => String(num).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export function toHourText(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "--";
  }
  return `${String(date.getHours()).padStart(2, "0")}:00`;
}

export function guessValue(raw) {
  const text = String(raw || "").trim();
  if (text === "") {
    return "";
  }
  if (text === "true") {
    return true;
  }
  if (text === "false") {
    return false;
  }
  if (/^-?\d+$/.test(text)) {
    return Number(text);
  }
  if ((text.startsWith("[") && text.endsWith("]")) || (text.startsWith("{") && text.endsWith("}"))) {
    try {
      return JSON.parse(text);
    } catch (_error) {
      return text;
    }
  }
  return text;
}
