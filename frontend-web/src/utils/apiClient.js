import { normalizeToken } from "./common";

function buildUrl(apiBase, path, query) {
  const url = new URL(path, apiBase);
  if (query && typeof query === "object") {
    Object.keys(query).forEach((key) => {
      if (query[key] === undefined || query[key] === null || query[key] === "") {
        return;
      }
      url.searchParams.set(key, String(query[key]));
    });
  }
  return url;
}

function buildRequestBody({ body, rawBody, contentType }) {
  if (rawBody !== null && rawBody !== undefined) {
    return {
      payload: rawBody,
      contentType: contentType || null,
    };
  }

  if (body === null || body === undefined) {
    return {
      payload: undefined,
      contentType: null,
    };
  }

  return {
    payload: JSON.stringify(body),
    contentType: contentType || "application/json",
  };
}

async function safeFetch(url, options) {
  try {
    return await fetch(url, options);
  } catch (_error) {
    throw new Error("请求失败，请检查 API Base、Vite 代理或后端 CORS 配置");
  }
}

export async function requestJson({
  apiBase,
  token,
  path,
  method = "GET",
  query = null,
  body = null,
  rawBody = null,
  contentType = null,
  withAuth = true,
}) {
  if (!apiBase) {
    throw new Error("API Base URL 未配置");
  }

  const url = buildUrl(apiBase, path, query);
  const headers = {};
  const requestBody = buildRequestBody({ body, rawBody, contentType });

  if (requestBody.contentType) {
    headers["Content-Type"] = requestBody.contentType;
  }

  if (withAuth && token) {
    headers.Authorization = normalizeToken(token);
  }

  const response = await safeFetch(url.toString(), {
    method,
    headers,
    body: requestBody.payload,
  });

  let payload = null;
  try {
    payload = await response.json();
  } catch (_error) {
    // ignore parse failure
  }

  if (!response.ok) {
    throw new Error(payload?.message || `HTTP ${response.status}`);
  }
  if (!payload || payload.success !== true) {
    throw new Error(payload?.message || "响应格式异常");
  }

  return payload.data;
}

export async function requestBlob({
  apiBase,
  token,
  path,
  method = "GET",
  query = null,
  body = null,
  rawBody = null,
  contentType = null,
  withAuth = true,
}) {
  if (!apiBase) {
    throw new Error("API Base URL 未配置");
  }

  const url = buildUrl(apiBase, path, query);
  const headers = {};
  const requestBody = buildRequestBody({ body, rawBody, contentType });

  if (withAuth && token) {
    headers.Authorization = normalizeToken(token);
  }

  if (requestBody.contentType) {
    headers["Content-Type"] = requestBody.contentType;
  }

  const response = await safeFetch(url.toString(), {
    method,
    headers,
    body: requestBody.payload,
  });

  if (!response.ok) {
    let payload = null;
    try {
      payload = await response.json();
    } catch (_error) {
      // ignore parse failure
    }
    throw new Error(payload?.message || `HTTP ${response.status}`);
  }

  return {
    blob: await response.blob(),
    contentType: response.headers.get("content-type") || "application/octet-stream",
    contentDisposition: response.headers.get("content-disposition") || "",
  };
}
