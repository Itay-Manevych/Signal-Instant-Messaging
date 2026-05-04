import assert from 'node:assert/strict';
import { activateSession, activeSession, createSesameSession, sessionById } from './sesameSession';
import type { DeviceAddress } from './sesameTypes';

class MemoryStorage {
  private values = new Map<string, string>();
  getItem(key: string) {
    return this.values.get(key) ?? null;
  }
  setItem(key: string, value: string) {
    this.values.set(key, value);
  }
  removeItem(key: string) {
    this.values.delete(key);
  }
  clear() {
    this.values.clear();
  }
}

Object.defineProperty(globalThis, 'localStorage', { value: new MemoryStorage() });

const alice: DeviceAddress = { userId: 'alice', deviceId: 'chrome' };
const bob: DeviceAddress = { userId: 'bob', deviceId: 'firefox' };

const first = createSesameSession(alice, bob, 'bob-identity', 'secret-1', 'session-a');
const second = createSesameSession(alice, bob, 'bob-identity', 'secret-2', 'session-b');

assert.equal(first.active, false);
assert.equal(second.active, false);
assert.equal(activeSession(alice, bob), null);

activateSession(alice, 'session-a');
assert.equal(activeSession(alice, bob)?.sessionId, 'session-a');

activateSession(alice, 'session-b');
assert.equal(activeSession(alice, bob)?.sessionId, 'session-b');
assert.equal(sessionById(alice, 'session-a')?.active, false);
assert.equal(sessionById(alice, 'session-b')?.active, true);

console.log('sesame session state tests passed');
