import { useCallback, useEffect, useRef, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import { errText } from './api';

/**
 * Poll a backend call and also refresh immediately when the backend says protection state changed.
 * The data always comes from the backend: pages never fabricate state.
 */
export function usePolled<T>(fn: () => Promise<T>, ms = 4000) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const reload = useCallback(async () => {
    try {
      setData(await fnRef.current());
      setError(null);
    } catch (e) {
      setError(errText(e));
    }
  }, []);

  useEffect(() => {
    void reload();
    const t = setInterval(() => void reload(), ms);
    const un = listen('protection-changed', () => void reload());
    return () => {
      clearInterval(t);
      void un.then((f) => f());
    };
  }, [reload, ms]);

  return { data, error, reload, setData };
}
