'use strict';

/** Fixed-window in-memory rate limiter. Good enough for a single-process deployment. */
class RateLimiter {
  constructor(limit, windowMs) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.hits = new Map();
    this.sweeper = setInterval(() => this.sweep(), Math.max(windowMs, 30000));
    this.sweeper.unref();
  }
  hit(key, now = Date.now()) {
    let e = this.hits.get(key);
    if (!e || e.reset <= now) {
      e = { count: 0, reset: now + this.windowMs };
      this.hits.set(key, e);
    }
    e.count++;
    return { ok: e.count <= this.limit, retryAfter: Math.max(1, Math.ceil((e.reset - now) / 1000)) };
  }
  sweep(now = Date.now()) {
    for (const [k, e] of this.hits) if (e.reset <= now) this.hits.delete(k);
  }
  stop() {
    clearInterval(this.sweeper);
  }
}

module.exports = { RateLimiter };
