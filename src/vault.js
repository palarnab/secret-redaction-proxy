'use strict';

/**
 * Per-request bijective map between real secret values and their
 * format-preserving fakes. The vault never leaves the process and is zeroized
 * once the response has been restored.
 */

const { generateFake } = require('./fakes');

class Vault {
  constructor() {
    this._realToFake = new Map(); // real value -> fake value
    this._fakeToReal = new Map(); // fake value -> real value
    this._meta = new Map(); // fake value -> { type }
  }

  /**
   * Register a real secret and return its fake. Idempotent per real value:
   * the same real string always maps to the same fake within a request.
   * Returns null if a fake could not be produced (caller may fail-closed).
   */
  tokenize(realValue, type) {
    if (realValue == null || realValue === '') return null;
    const existing = this._realToFake.get(realValue);
    if (existing) return existing;

    let fake;
    try {
      fake = generateFake(type, realValue);
    } catch {
      return null;
    }
    if (!fake || fake === realValue) return null;

    // Guarantee collision-freedom against already-registered fakes/reals.
    let guard = 0;
    while (
      this._fakeToReal.has(fake) ||
      this._realToFake.has(fake) ||
      fake === realValue
    ) {
      fake = generateFake(type, realValue);
      if (++guard > 8) return null;
    }

    this._realToFake.set(realValue, fake);
    this._fakeToReal.set(fake, realValue);
    this._meta.set(fake, { type });
    return fake;
  }

  /** All fake values currently registered (for restore scanning). */
  fakes() {
    return Array.from(this._fakeToReal.keys());
  }

  realFor(fake) {
    return this._fakeToReal.get(fake);
  }

  get size() {
    return this._realToFake.size;
  }

  /** Best-effort zeroization; clears references so GC can reclaim. */
  zeroize() {
    this._realToFake.clear();
    this._fakeToReal.clear();
    this._meta.clear();
  }
}

module.exports = { Vault };
