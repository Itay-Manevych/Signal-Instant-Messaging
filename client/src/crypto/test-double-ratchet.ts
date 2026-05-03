/**
 * Ping-pong: X3DH (Bob sends first) then Double Ratchet encrypt/decrypt.
 */

import { generateIdentityKeyPair, generateOneTimePreKeyPair, generateSignedPreKeyPair, generateX25519KeyPair } from './signalKeys';
import { sign } from './signalCrypto';
import { initializeSenderSession, initializeReceiverSession } from './x3dh';
import { DoubleRatchetSession } from './doubleRatchet';

const textEncoder = new TextEncoder();

async function main(): Promise<void> {
  console.log('🚀 X3DH + Double Ratchet integration test...\n');

  const aliceIk = generateIdentityKeyPair();
  const aliceSpk = generateSignedPreKeyPair();
  const aliceOpk = generateOneTimePreKeyPair();
  const aliceSpkSig = sign(aliceIk.privateKey, aliceSpk.publicKey);

  const aliceBundle = {
    identityPublicKey: aliceIk.publicKey,
    signedPreKeyPublicKey: aliceSpk.publicKey,
    signedPreKeySignature: aliceSpkSig,
    oneTimePreKeyId: 'opk-dr-1',
    oneTimePreKeyPublicKey: aliceOpk.publicKey,
  };

  const bobIk = generateIdentityKeyPair();

  const bobX3dh = initializeSenderSession(bobIk.privateKey, aliceBundle);

  const skBob = bobX3dh.sharedSecret;

  const skAlice = initializeReceiverSession(
    aliceIk.privateKey,
    aliceSpk.privateKey,
    aliceOpk.privateKey,
    bobIk.publicKey,
    bobX3dh.ephemeralPublicKey,
  );

  if (Buffer.from(skAlice).toString('base64') !== Buffer.from(skBob).toString('base64')) {
    console.error('❌ X3DH SK mismatch before ratchet.');
    process.exit(1);
  }

  console.log('✓ X3DH SK aligned.\n');

  const dhPairFn = (): ReturnType<typeof generateX25519KeyPair> => generateX25519KeyPair();

  // Bob initiated X3DH → Bob sends DR messages first. Initiator uses recipient’s SPK pubkey as initial DHr (§7.1).
  const bobDr = DoubleRatchetSession.createInitiator(skBob, aliceSpk.publicKey, dhPairFn);
  const aliceDr = DoubleRatchetSession.createResponder(skAlice, aliceSpk, dhPairFn);

  const AD = textEncoder.encode('sim-instant-msg');

  const b1pt = textEncoder.encode('hello alice');
  const b1 = await bobDr.ratchetEncrypt(b1pt, AD);

  let a1decoded: Uint8Array;
  try {
    a1decoded = await aliceDr.ratchetDecrypt(b1.headerBytes, b1.ciphertext, AD);
  } catch (e) {
    console.error('❌ alice decrypt bob#1:', e);
    process.exit(1);
  }

  if (Buffer.from(a1decoded).toString() !== Buffer.from(b1pt).toString()) {
    console.error('❌ plaintext mismatch bob→alice.');
    process.exit(1);
  }
  console.log('✓ Bob → Alice decrypted:', Buffer.from(a1decoded).toString());

  const aReply = textEncoder.encode('hi bob');
  const a1enc = await aliceDr.ratchetEncrypt(aReply, AD);

  let bobDec: Uint8Array;
  try {
    bobDec = await bobDr.ratchetDecrypt(a1enc.headerBytes, a1enc.ciphertext, AD);
  } catch (e) {
    console.error('❌ bob decrypt alice#1:', e);
    process.exit(1);
  }

  if (Buffer.from(bobDec).toString() !== Buffer.from(aReply).toString()) {
    console.error('❌ plaintext mismatch alice→bob.');
    process.exit(1);
  }
  console.log('✓ Alice → Bob decrypted:', Buffer.from(bobDec).toString());

  console.log('\n✅ Double Ratchet round-trip succeeded.');
}

main().catch((e) => {
  console.error('💥', e);
  process.exit(1);
});
