import { generateEphemeralKeyPair, toBase64 } from './signalKeys.js';
import { initializeRatchet, ratchetEncrypt, ratchetDecrypt, serializeRatchetState, deserializeRatchetState } from './doubleRatchet.js';
import { randomBytes } from './signalCrypto.js';

async function testPersistence() {
  console.log('🚀 Starting Double Ratchet Persistence Test...');

  const sharedSecret = randomBytes(32);
  const aliceDH = generateEphemeralKeyPair();
  const bobDH = generateEphemeralKeyPair();

  let aliceState = initializeRatchet(sharedSecret, true, bobDH.publicKey, aliceDH);
  let bobState = initializeRatchet(sharedSecret, false, aliceDH.publicKey, bobDH);

  console.log('--- Alice sends 1 message ---');
  const msg1 = ratchetEncrypt(aliceState);
  
  console.log('--- Bob deserializes and decrypts ---');
  const serializedBob = serializeRatchetState(bobState);
  const bobStateClone = deserializeRatchetState(serializedBob);
  
  const key1 = ratchetDecrypt(bobStateClone, msg1.header);
  console.log(`[Bob] Decrypting #1: ${toBase64(key1) === toBase64(msg1.messageKey) ? '✅ SUCCESS' : '❌ FAILED'}`);

  console.log('--- Alice deserializes and sends another ---');
  const serializedAlice = serializeRatchetState(aliceState);
  const aliceStateClone = deserializeRatchetState(serializedAlice);
  
  const msg2 = ratchetEncrypt(aliceStateClone);
  
  console.log('--- Bob decrypts #2 with clone ---');
  const key2 = ratchetDecrypt(bobStateClone, msg2.header);
  console.log(`[Bob] Decrypting #2: ${toBase64(key2) === toBase64(msg2.messageKey) ? '✅ SUCCESS' : '❌ FAILED'}`);

  if (toBase64(key2) !== toBase64(msg2.messageKey)) {
      throw new Error('Persistence test failed!');
  }

  console.log('✅ FINAL RESULT: Persistence is working!');
}

testPersistence().catch(err => {
  console.error('\n❌ TEST FAILED');
  console.error(err);
  process.exit(1);
});
