import { useChat } from '../context/ChatContext';
import { fetchPreKeyBundle } from '../api';
import { encryptMessage, initializeRatchet } from '../crypto/doubleRatchet';
import { initializeSenderSession } from '../crypto/x3dh';
import { fromBase64, toBase64, generateOneTimePreKeyPair } from '../crypto/signalKeys';
import { saveSessionState, getSession } from '../utils';
import type { ChatMessage, Session } from '../types';

export function useSendMessage(
  session: Session | null,
  recipientId: string,
  getKeys: () => any,
  sendMessage: (payload: any) => void
) {
  const { setThreads, setWsError } = useChat();

  const handleSend = async (draft: string) => {
    const text = draft.trim();
    if (!text || !recipientId || !session) return;

    try {
      const myKeys = getKeys();
      if (!myKeys) throw new Error('Signal keys not found locally');

      let ratchetState = getSession(recipientId);
      let x3dhHeader = undefined;

      if (!ratchetState) {
        console.log('🔄 No session found. Starting X3DH handshake with', recipientId);
        const bundle = await fetchPreKeyBundle(session.token, recipientId);
        
        const ek = generateOneTimePreKeyPair();
        const handshake = initializeSenderSession(
          fromBase64(myKeys.identityKey.privateKeyB64),
          {
            identityPublicKey: fromBase64(bundle.identityKey.publicKeyB64),
            signedPreKeyPublicKey: fromBase64(bundle.signedPreKey.publicKeyB64),
            signedPreKeySignature: fromBase64(bundle.signedPreKey.signatureB64),
            oneTimePreKeyId: bundle.oneTimePreKey?.id.toString(),
            oneTimePreKeyPublicKey: bundle.oneTimePreKey ? fromBase64(bundle.oneTimePreKey.publicKeyB64) : undefined,
          },
          ek
        );

        console.log('🤝 Handshake Shared Secret (DEBUG: Temporary):', toBase64(handshake.sharedSecret));

        ratchetState = initializeRatchet(
          handshake.sharedSecret,
          true,
          fromBase64(bundle.signedPreKey.publicKeyB64),
          ek
        );

        x3dhHeader = {
          identityKeyB64: myKeys.identityKey.publicKeyB64,
          ephemeralKeyB64: toBase64(ek.publicKey),
          oneTimePreKeyId: bundle.oneTimePreKey?.id,
        };
      }

      const { ciphertextB64, ivB64, header } = await encryptMessage(ratchetState, text);
      
      const payload = {
        type: 'chat',
        toUserId: recipientId,
        ciphertext: ciphertextB64,
        header: {
          dhPublicKeyB64: toBase64(header.dhPublicKey),
          pn: header.pn,
          n: header.n,
          ivB64,
          x3dh: x3dhHeader,
        }
      };
      
      sendMessage(payload);

      const localMsg: ChatMessage = {
        type: 'chat',
        id: `local-${Date.now()}`,
        fromUserId: session.userId,
        fromUsername: session.username,
        toUserId: recipientId,
        text,
        ciphertext: ciphertextB64,
        header: payload.header,
        sentAt: new Date().toISOString(),
      };

      setThreads((prev) => {
        const list = prev[recipientId] ?? [];
        return { ...prev, [recipientId]: [...list, localMsg] };
      });

      saveSessionState(recipientId, ratchetState);
    } catch (err) {
      console.error('❌ Failed to send message:', err);
      setWsError('Encryption error - see console');
    }
  };

  return { handleSend };
}
