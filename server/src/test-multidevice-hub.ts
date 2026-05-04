import assert from 'node:assert/strict';
import { ConnectionHub, type ClientSocket } from './store.js';

function socket(name: string, inbox: string[]): ClientSocket {
  return {
    send(data: string) {
      inbox.push(`${name}:${data}`);
    },
    close() {
      inbox.push(`${name}:closed`);
    },
  };
}

const hub = new ConnectionHub();
const inbox: string[] = [];

hub.add('alice', 'chrome', socket('chrome', inbox));
hub.add('alice', 'firefox', socket('firefox', inbox));

assert.equal(hub.isOnline('alice'), true);
assert.deepEqual(hub.onlineUserIds(), ['alice']);
assert.equal(hub.sendToDevice('alice', 'chrome', { hello: 'chrome' }), true);
assert.equal(hub.sendToDevice('alice', 'firefox', { hello: 'firefox' }), true);
assert.equal(hub.sendToDevice('alice', 'safari', { hello: 'safari' }), false);
assert.equal(inbox.length, 2);

const chrome2 = socket('chrome2', inbox);
hub.add('alice', 'chrome', chrome2);
assert.equal(hub.sendToDevice('alice', 'chrome', { hello: 'both-tabs' }), true);
assert.equal(inbox[2], 'chrome:{"hello":"both-tabs"}');
assert.equal(inbox[3], 'chrome2:{"hello":"both-tabs"}');

hub.remove('alice', 'chrome', chrome2);
assert.equal(hub.sendToDevice('alice', 'chrome', { still: true }), true);
assert.equal(hub.sendToDevice('alice', 'firefox', { ok: true }), true);

console.log('multi-device hub tests passed');
