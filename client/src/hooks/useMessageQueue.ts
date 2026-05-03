import { useRef, useCallback } from 'react';
import { useChat } from '../context/ChatContext';
import { initializeRatchet, decryptMessage } from '../crypto/doubleRatchet';
import { initializeReceiverSession } from '../crypto/x3dh';
import { fromBase64 } from '../crypto/signalCrypto';
import { getKeys, getSession, saveSessionState } from '../utils';
import type { Session, ChatMessage } from '../types';

export function useMessageQueue(session: Session | null) {
  const { setThreads, setPeerList, setWsError } = useChat();
  const messageQueue = useRef<any[]>([]);
  const isProcessing = useRef(false);

  const peerIdForMessage = (msg: ChatMessage, selfId: string): string => {
    return msg.fromUserId === selfId ? msg.toUserId : msg.fromUserId;
  };

  const processQueue = useCallback(async () => {
    if (!session || isProcessing.current || messageQueue.current.length === 0) return;
    isProcessing.current = true;

    try {
      while (messageQueue.current.length > 0) {
        const msg = messageQueue.current.shift()!;
        const peerId = peerIdForMessage(msg, session.userId);

        if (msg.ciphertext && msg.header) {
          if (msg.fromUserId === session.userId) {
            // Outgoing echo logic
            setThreads((prev) => {
              const list = prev[peerId] ?? [];
              const idx = list.findIndex(m => m.id.startsWith('local-') && m.ciphertext === msg.ciphertext);
              if (idx !== -1) {
                const newList = [...list];
                newList[idx] = { ...msg, text: list[idx].text ?? '' };
                return { ...prev, [peerId]: newList };
              }
              return prev;
            });
          } else {
            // Incoming message logic
            try {
              const myKeys = getKeys(session.userId);
              let currentState = getSession(peerId);
              const x3dh = msg.header.x3dh;

              if (x3dh) {
                console.log('🔄 X3DH header detected. Initializing/Resetting session for', peerId);
                let otpkPriv = null;
                if (x3dh.oneTimePreKeyId !== undefined) {
                  const targetId = Number(x3dh.oneTimePreKeyId);
                  const found = myKeys?.oneTimePreKeys.find((k: any) => Number(k.id) === targetId);
                  if (found) {
                    otpkPriv = fromBase64(found.privateKeyB64);
                    console.log('🗝️ Found matching One-Time Pre-Key ID:', targetId);
                  }
                }

                const sharedSecret = initializeReceiverSession(
                  fromBase64(myKeys.identityKey.privateKeyB64),
                  fromBase64(myKeys.signedPreKey.privateKeyB64),
                  otpkPriv,
                  fromBase64(x3dh.identityKeyB64),
                  fromBase64(x3dh.ephemeralKeyB64)
                );
                
                console.log('🤝 Handshake Shared Secret (DEBUG: Temporary):', (await import('../crypto/signalCrypto')).toBase64(sharedSecret));

                currentState = initializeRatchet(
                  sharedSecret,
                  false,
                  fromBase64(x3dh.ephemeralKeyB64),
                  {
                    publicKey: fromBase64(myKeys.signedPreKey.publicKeyB64),
                    privateKey: fromBase64(myKeys.signedPreKey.privateKeyB64),
                  }
                );
              }

              if (currentState) {
                const text = await decryptMessage(
                  currentState,
                  {
                    dhPublicKey: fromBase64(msg.header.dhPublicKeyB64),
                    pn: msg.header.pn,
                    n: msg.header.n,
                  },
                  msg.ciphertext,
                  msg.header.ivB64
                );
                msg.text = text;
                saveSessionState(peerId, currentState);
              } else {
                msg.text = '[Secure session not initialized]';
              }
            } catch (err) {
              console.error('❌ Decryption failed:', err);
              msg.text = '[Decryption failed]';
            }

            setThreads((prev) => {
              const list = prev[peerId] ?? [];
              if (list.some(m => m.id === msg.id)) return prev;
              return { ...prev, [peerId]: [...list, msg] };
            });
          }
        }

        if (msg.fromUserId !== session.userId) {
          setPeerList((prev) => {
            if (prev.some((p) => p.id === msg.fromUserId)) return prev;
            return [...prev, { id: msg.fromUserId, username: msg.fromUsername }];
          });
        }
      }
    } finally {
      isProcessing.current = false;
      if (messageQueue.current.length > 0) void processQueue();
    }
  }, [session, setThreads, setPeerList, setWsError]);

  const enqueue = useCallback((msg: any) => {
    messageQueue.current.push(msg);
    void processQueue();
  }, [processQueue]);

  return { enqueue };
}
