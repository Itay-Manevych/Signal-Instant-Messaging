import assert from 'node:assert/strict';

type Device = { user: string; device: string; linkedAt: number };
type Msg = { text: string; sender: Device; recipientUser: string; sentAt: number; encryptedTo: string[] };

function id(d: Device) {
  return `${d.user}:${d.device}`;
}

function send(text: string, sender: Device, recipientUser: string, sentAt: number, devices: Device[]): Msg {
  return {
    text,
    sender,
    recipientUser,
    sentAt,
    encryptedTo: devices.filter((d) => d.user === recipientUser && d.linkedAt <= sentAt).map(id),
  };
}

function canRead(device: Device, msg: Msg) {
  return msg.sender.user === device.user || msg.encryptedTo.includes(id(device));
}

const eyalChrome = { user: 'eyal', device: 'chrome', linkedAt: 1 };
const bobFirefox = { user: 'bob', device: 'firefox', linkedAt: 1 };
const msgBeforeBobEdge = send('before edge', eyalChrome, 'bob', 2, [eyalChrome, bobFirefox]);
const bobEdge = { user: 'bob', device: 'edge', linkedAt: 3 };
const msgAfterBobEdge = send('after edge', eyalChrome, 'bob', 4, [eyalChrome, bobFirefox, bobEdge]);

assert.equal(canRead(bobFirefox, msgBeforeBobEdge), true);
assert.equal(canRead(bobEdge, msgBeforeBobEdge), false);
assert.equal(canRead(bobEdge, msgAfterBobEdge), true);

console.log('Sesame visibility demo: new devices read future messages, not old encrypted history.');
