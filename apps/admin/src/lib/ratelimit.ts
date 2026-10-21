import { q } from './db';

/** Fixed-window limiter backed by Postgres so it holds across serverless instances. Returns true if allowed. */
export async function allow(bucket: string, limit: number, windowSec: number): Promise<boolean> {
  const rows = await q<{ count: number }>(
    `INSERT INTO rate_limits(bucket, count, window_end) VALUES ($1, 1, now() + make_interval(secs => $2))
     ON CONFLICT (bucket) DO UPDATE SET
       count      = CASE WHEN rate_limits.window_end < now() THEN 1 ELSE rate_limits.count + 1 END,
       window_end = CASE WHEN rate_limits.window_end < now() THEN now() + make_interval(secs => $2) ELSE rate_limits.window_end END
     RETURNING count`,
    [bucket, windowSec],
  );
  return rows[0].count <= limit;
}
