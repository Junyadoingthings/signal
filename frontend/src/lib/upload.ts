import { ApiError, getCsrfToken, type ApiErrorBody } from "./api";
import type { Batch } from "./types";

export interface UploadOptions {
  file: File;
  format: string;
  host?: string;
  fieldMapping?: Record<string, string>;
  onProgress?: (fraction: number) => void;
  signal?: AbortSignal;
}

/** XHR rather than fetch: fetch can't report upload progress. */
export function uploadFile(opts: UploadOptions): Promise<Batch> {
  return new Promise((resolve, reject) => {
    const form = new FormData();
    form.append("file", opts.file);
    form.append("format", opts.format);
    if (opts.host) form.append("host", opts.host);
    if (opts.fieldMapping) form.append("field_mapping", JSON.stringify(opts.fieldMapping));

    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/ingest/upload");
    xhr.withCredentials = true;
    const csrf = getCsrfToken();
    if (csrf) xhr.setRequestHeader("X-CSRF-Token", csrf);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) opts.onProgress?.(e.loaded / e.total);
    };
    xhr.onload = () => {
      let body: unknown = null;
      try {
        body = JSON.parse(xhr.responseText);
      } catch {
        /* non-JSON error page */
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(body as Batch);
      } else {
        const err =
          body && typeof body === "object" && "error" in body
            ? (body as { error: ApiErrorBody }).error
            : { code: "http_error", message: `Upload failed (${xhr.status})` };
        reject(new ApiError(xhr.status, err));
      }
    };
    xhr.onerror = () => {
      reject(new ApiError(0, { code: "network_error", message: "Network error during upload" }));
    };
    opts.signal?.addEventListener("abort", () => {
      xhr.abort();
    });
    xhr.send(form);
  });
}
