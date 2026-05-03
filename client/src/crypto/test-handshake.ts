import { generateIdentityKeyPair, generateSignedPreKeyPair, generateOneTimePreKeyPair, toBase64 } from './signalKeys';
import { sign } from './signalCrypto';
import { initializeSenderSession, initializeReceiverSession } from './x3dh';

function testX3DH() {
  try {
    console.log("🚀 Starting X3DH Protocol Integration Test...");

    // 1. ALICE (Receiver) GENERATES LONG-TERM KEYS
    const aliceIK = generateIdentityKeyPair();
    const aliceSPK = generateSignedPreKeyPair();
    const aliceOPK = generateOneTimePreKeyPair();

    // Alice signs her SPK with her Identity Key (XEdDSA)
    const aliceSPKSig = sign(aliceIK.privateKey, aliceSPK.publicKey);

    // This is the "Pre-Key Bundle" that the server would store for Alice
    const aliceBundle = {
      identityPublicKey: aliceIK.publicKey,
      signedPreKeyPublicKey: aliceSPK.publicKey,
      signedPreKeySignature: aliceSPKSig,
      oneTimePreKeyId: "opk-test-1",
      oneTimePreKeyPublicKey: aliceOPK.publicKey,
    };

    // 2. BOB (Sender) WANTS TO CHAT WITH ALICE
    const bobIK = generateIdentityKeyPair();

    // Bob fetches Alice's bundle and runs the sender-side handshake
    const bobResult = initializeSenderSession(bobIK.privateKey, aliceBundle);
    const bobSecret = bobResult.sharedSecret;

    // 3. ALICE RECEIVES BOB'S INITIAL MESSAGE
    // Bob would send his Identity Public Key and his Ephemeral Public Key to Alice
    const aliceSecret = initializeReceiverSession(
      aliceIK.privateKey,
      aliceSPK.privateKey,
      aliceOPK.privateKey,
      bobIK.publicKey,
      bobResult.ephemeralPublicKey
    );

    // 4. VERIFICATION
    const aliceSecretB64 = toBase64(aliceSecret);
    const bobSecretB64 = toBase64(bobSecret);

    console.log("🔑 Alice's Shared Secret:", aliceSecretB64);
    console.log("🔑 Bob's Shared Secret:  ", bobSecretB64);

    if (aliceSecretB64 === bobSecretB64) {
      console.log("✅ SUCCESS: Shared secrets match (DH + X3DH KDF per Signal spec §2.2).");
      process.exit(0);
    } else {
      console.error("❌ FAILURE: Shared secrets do not match.");
      process.exit(1);
    }
  } catch (error) {
    console.error("💥 TEST CRASHED:", error);
    process.exit(1);
  }
}

testX3DH();
