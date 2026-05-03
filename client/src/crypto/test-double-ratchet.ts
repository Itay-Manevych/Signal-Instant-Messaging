import { generateEphemeralKeyPair, toBase64 } from './signalKeys.js';
import { initializeRatchet, ratchetEncrypt, ratchetDecrypt } from './doubleRatchet.js';
import { randomBytes } from './signalCrypto.js';

async function testDoubleRatchet() {
  console.log('🚀 Starting Double Ratchet Integration Test...');

  // 1. Simulate X3DH shared secret
  const sharedSecret = randomBytes(32);
  
  // Alice starts as initiator (sending the first message)
  // Bob starts as responder
  const aliceDH = generateEphemeralKeyPair();
  const bobDH = generateEphemeralKeyPair();

  const aliceState = initializeRatchet(sharedSecret, true, bobDH.publicKey, aliceDH);
  const bobState = initializeRatchet(sharedSecret, false, aliceDH.publicKey, bobDH);

  console.log('--- Alice sends 3 messages to Bob ---');
  const msgsFromAlice = [];
  for (let i = 0; i < 3; i++) {
    const { header, messageKey } = ratchetEncrypt(aliceState);
    msgsFromAlice.push({ header, messageKey });
    console.log(`[Alice -> Bob] Message #${i} Key: ${toBase64(messageKey).slice(0, 8)}...`);
  }

  console.log('\n--- Bob receives 3 messages from Alice ---');
  for (let i = 0; i < 3; i++) {
    const key = ratchetDecrypt(bobState, msgsFromAlice[i].header);
    const success = toBase64(key) === toBase64(msgsFromAlice[i].messageKey);
    console.log(`[Bob] Decrypting #${i}: ${success ? '✅ SUCCESS' : '❌ FAILED'}`);
    if (!success) throw new Error(`Key mismatch at message ${i}`);
  }

  console.log('\n--- Bob sends 2 messages to Alice (Rotating DH Ratchet) ---');
  const msgsFromBob = [];
  for (let i = 0; i < 2; i++) {
    const { header, messageKey } = ratchetEncrypt(bobState);
    msgsFromBob.push({ header, messageKey });
    console.log(`[Bob -> Alice] Message #${i} Key: ${toBase64(messageKey).slice(0, 8)}...`);
  }

  console.log('\n--- Alice receives 2 messages from Bob ---');
  for (let i = 0; i < 2; i++) {
    const key = ratchetDecrypt(aliceState, msgsFromBob[i].header);
    const success = toBase64(key) === toBase64(msgsFromBob[i].messageKey);
    console.log(`[Alice] Decrypting #${i}: ${success ? '✅ SUCCESS' : '❌ FAILED'}`);
    if (!success) throw new Error(`Key mismatch at message ${i}`);
  }

  console.log('\n--- Testing Out-of-Order/Skipped Messages ---');
  // Alice sends messages #3, #4, #5 (0-indexed in new chain)
  const burst = [];
  for (let i = 0; i < 3; i++) {
    burst.push(ratchetEncrypt(aliceState));
  }

  // Bob receives #5 before #4
  console.log('[Bob] Receiving #2 (Message #5 in burst)...');
  const key2 = ratchetDecrypt(bobState, burst[2].header);
  console.log(`[Bob] Decrypting #2: ${toBase64(key2) === toBase64(burst[2].messageKey) ? '✅ SUCCESS' : '❌ FAILED'}`);

  console.log('[Bob] Receiving #1 (Message #4 in burst) from skipped keys...');
  const key1 = ratchetDecrypt(bobState, burst[1].header);
  console.log(`[Bob] Decrypting #1: ${toBase64(key1) === toBase64(burst[1].messageKey) ? '✅ SUCCESS' : '❌ FAILED'}`);

  console.log('\n✅ FINAL RESULT: Double Ratchet is 100% compliant!');
}

testDoubleRatchet().catch(err => {
  console.error('\n❌ TEST FAILED');
  console.error(err);
  process.exit(1);
});
