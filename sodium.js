function u8ToBuf(u8) {
  return Buffer.isBuffer(u8)
    ? u8
    : Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength)
}

let api = null

/* INFO: using sodium-native first because its more performant than libsodium-wrappers, but if it fails to load
  (e.g. not supported platform), it will fallback to libsodium-wrappers. Sodium-native is preffered because it
  allows writing directly into libsodium buffers.

  USAGE ENCRYPT: const clen = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      c,        // c: output buffer for ciphertext
      m,        // m: input message buffer
      ad,       // ad: additional data (optional, can be null)
      null,     // nsec: must be null
      npub,     // npub: public nonce
      k         // k: private key
  )

  USAGE DECRYPT: const mlen = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      m,        // m: output buffer for message
      null,     // nsec: must be null
      c,        // c: input ciphertext buffer
      ad,       // ad: additional data (optional, can be null)
      npub,     // npub: public nonce
      k         // k: private key
  )

  SOURCES:
        - https://sodium-friends.github.io/docs/docs/aead
        - https://sodium-friends.github.io/docs/docs/aead#crypto_aead_xchacha20poly1305_ietf_decrypt
*/
try {
  const mod = await import('sodium-native')
  const sodium = mod.default ?? mod
  const ABYTES = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES

  api = {
    kind: 'sodium-native',
    ABYTES,
    crypto_aead_xchacha20poly1305_ietf_encrypt_into(out, msg, aad, nonce, key) {
      sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(out, msg, aad, null, nonce, key)
      return out
    },
    crypto_aead_xchacha20poly1305_ietf_encrypt(msg, aad, nonce, key) {
      const out = Buffer.allocUnsafe(msg.length + ABYTES)
      sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        out,
        msg,
        aad,
        null,
        nonce,
        key
      )
      return out
    },
    crypto_aead_xchacha20poly1305_ietf_decrypt(cipher, aad, nonce, key) {
      const out = Buffer.allocUnsafe(cipher.length - ABYTES)
      const ok = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        out,
        null,
        cipher,
        aad,
        nonce,
        key
      )
      if (ok === false) throw new Error('sodium decrypt failed')
      return out
    }
  }
} catch {
  // ignore, it will fallback to libsodium-wrappers
}

if (!api) {
  const mod = await import('libsodium-wrappers')
  const sodium = mod.default ?? mod
  await sodium.ready
  const ABYTES = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES

  api = {
    kind: 'libsodium-wrappers',
    ABYTES,
    crypto_aead_xchacha20poly1305_ietf_encrypt_into(out, msg, aad, nonce, key) {
      const enc = u8ToBuf(
        sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
          msg,
          aad,
          null,
          nonce,
          key
        )
      )
      enc.copy(out)
      return out
    },
    crypto_aead_xchacha20poly1305_ietf_encrypt(msg, aad, nonce, key) {
      return u8ToBuf(
        sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
          msg,
          aad,
          null,
          nonce,
          key
        )
      )
    },
    crypto_aead_xchacha20poly1305_ietf_decrypt(cipher, aad, nonce, key) {
      return u8ToBuf(
        sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
          null,
          cipher,
          aad,
          nonce,
          key
        )
      )
    }
  }
}

export default api
