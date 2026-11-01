import { useCallback, useEffect, useState } from "react";
import { useApi } from "./context";

export interface Loaded<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

/** GET ``path`` whenever it changes; ``null`` skips the request. While a request is in
 * flight, ``data`` is null (the result belongs to the request that produced it). */
export function useData<T>(path: string | null): Loaded<T> {
  const api = useApi();
  const [version, setVersion] = useState(0);
  const reload = useCallback(() => setVersion((v) => v + 1), []);
  const key = path === null ? null : `${version}:${path}`;
  const [result, setResult] = useState<{ key: string | null; data: T | null; error: string | null }>({
    key: null,
    data: null,
    error: null,
  });

  useEffect(() => {
    if (path === null || key === null) return;
    let active = true;
    api.get<T>(path).then(
      (data) => active && setResult({ key, data, error: null }),
      (error: unknown) =>
        active &&
        setResult({ key, data: null, error: error instanceof Error ? error.message : "Request failed" }),
    );
    return () => {
      active = false;
    };
  }, [api, path, key]);

  const current = result.key === key;
  return {
    data: current ? result.data : null,
    error: current ? result.error : null,
    loading: key !== null && !current,
    reload,
  };
}
