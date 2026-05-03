import { useState, useEffect, useRef } from 'react';
import type { Session } from '../types';
import { 
  generateIdentityKeyPair, 
  generateSignedPreKeyPair, 
  generateOneTimePreKeyPair, 
  toBase64 
} from '../crypto/signalKeys';
import { sign } from '../crypto/signalCrypto';
import { getKeys } from '../utils';
import { publishKeys } from '../api';

export function useSignalKeys(session: Session | null) {
  const enrollingRef = useRef(false);

  useEffect(() => {
    if (!session) return;
    
    const enroll = async () => {
      if (enrollingRef.current) return;
      
      if (getKeys(session.userId)) return;

      enrollingRef.current = true;
      console.log('🗝️ Generating new Signal keys for', session.username);
      
      try {
        const ik = generateIdentityKeyPair();
        const spk = generateSignedPreKeyPair(ik.privateKey);
        const otpk = generateOneTimePreKeyPair();

        const bundle = {
          identityKey: {
            publicKeyB64: toBase64(ik.publicKey),
            privateKeyB64: toBase64(ik.privateKey),
          },
          signedPreKey: {
            publicKeyB64: toBase64(spk.publicKey),
            privateKeyB64: toBase64(spk.privateKey),
            signatureB64: toBase64(sign(ik.privateKey, spk.publicKey)),
          },
          oneTimePreKeys: [
            {
              id: 1,
              publicKeyB64: toBase64(otpk.publicKey),
              privateKeyB64: toBase64(otpk.privateKey),
            }
          ]
        };

        await publishKeys(session.token, {
          identityPublicKeyB64: bundle.identityKey.publicKeyB64,
          signedPreKey: {
            publicKeyB64: bundle.signedPreKey.publicKeyB64,
            signatureB64: bundle.signedPreKey.signatureB64,
          },
          oneTimePreKeys: bundle.oneTimePreKeys.map(k => ({
            id: k.id,
            publicKeyB64: k.publicKeyB64,
          })),
        });

        localStorage.setItem(`signal-keys-${session.userId}`, JSON.stringify(bundle));
        console.log('✅ Keys published and saved.');
      } catch (err) {
        console.error('❌ Failed to publish keys:', err);
      } finally {
        enrollingRef.current = false;
      }
    };

    void enroll();
  }, [session]);

  return { getKeys: () => session ? getKeys(session.userId) : null };
}
