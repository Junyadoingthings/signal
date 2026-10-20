/**
 * Thin fetch wrapper. Same-origin only (dev proxy / nginx), cookies sent automatically,
 * CSRF token attached to every state-changing request.
 */

export interface ApiErrorBody {
  code: string;
  message: string;
  details?: unknown;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: unknown;

  constructor(status: number, body: ApiErrorBody) {
    super(body.message);
    this.status = status;
    this.code = body.code;
    this.details = body.details;
  }
}

let csrfToken: string | null = null;
let onUnauthenticated: (() => void) | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

export function setUnauthenticatedHandler(fn: (() => void) | null): void {
  onUnauthenticated = fn;
}

type Method = "GET" | "POST" | "PATCH" | "PUT" | "DELETE";

async function request<T>(method: Method, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;

  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? null : JSON.stringify(body),
  });

  if (res.status === 204) return undefined as T;

  const isJson = res.headers.get("content-type")?.includes("application/json") ?? false;
  const data: unknown = isJson ? await res.json() : null;

  if (!res.ok) {
    const err =
      data && typeof data === "object" && "error" in data
        ? (data as { error: ApiErrorBody }).error
        : { code: "http_error", message: `Request failed (${res.status})` };
    if (res.status === 401 && path !== "/api/auth/login") onUnauthenticated?.();
    throw new ApiError(res.status, err);
  }
  return data as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),
  patch: <T>(path: string, body?: unknown) => request<T>("PATCH", path, body),
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, body),
  delete: <T>(path: string) => request<T>("DELETE", path),
};
