/** @format */

import isBuffer from 'is-buffer'
import {Buffer} from 'safe-buffer'

export default function() {
  var secp256k1 = {}
  const s = window.SECP256K1().then(() => {
    secp256k1.s = s

    Object.defineProperties(secp256k1, {
      s: {
        writable: false,
        value: s
      },
      ctx: {
        writable: false,
        value: s._secp256k1_context_create(769)
      },
      msgLen: {
        writable: false,
        value: 32
      },
      privkeyLen: {
        writable: false,
        value: 32
      },
      rawSigLen: {
        writable: false,
        value: 64
      },
      sigLen: {
        writable: false,
        value: 65
      },
      pubkeyLen: {
        writable: false,
        value: 64
      },
      SECP256K1_EC_COMPRESSED: {
        writable: false,
        value: 258
      },
      SECP256K1_EC_UNCOMPRESSED: {
        writable: false,
        value: 2
      }
    })

    secp256k1.copyToBuffer = function(src, len) {
      let out = new Buffer(len)
      for (var i = 0; i < len; i++) {
        let v = secp256k1.s.getValue(src + i, 'i8')
        out[i] = v
      }
      return out
    }

    secp256k1._sign = function(msgBuf, privkeyBuf) {
      if (
        isBuffer(privkeyBuf) !== true ||
        privkeyBuf.length !== secp256k1.privkeyLen
      ) {
        return false
      }
      if (isBuffer(msgBuf) !== true || msgBuf.length !== secp256k1.msgLen) {
        return false
      }
      // verify private key
      let privkey = secp256k1.s._malloc(secp256k1.privkeyLen)
      let msg = secp256k1.s._malloc(secp256k1.msgLen)
      secp256k1.s.HEAP8.set(privkeyBuf, privkey)
      secp256k1.s.HEAP8.set(msgBuf, msg)
      if (
        secp256k1.s._secp256k1_ec_seckey_verify(secp256k1.ctx, privkey) !== 1
      ) {
        secp256k1.s._free(privkey)
        secp256k1.s._free(msg)
        return false
      }
      let rawSig = secp256k1.s._malloc(secp256k1.sigLen)
      if (
        secp256k1.s._secp256k1_ecdsa_sign_recoverable(
          secp256k1.ctx,
          rawSig,
          msg,
          privkey,
          null,
          null
        ) !== 1
      ) {
        secp256k1.s._free(privkey)
        secp256k1.s._free(msg)
        secp256k1.s._free(rawSig)
        return false
      }

      secp256k1.s._free(privkey)
      secp256k1.s._free(msg)

      // turn recoverable signature into a normal signature
      let sig = secp256k1.s._malloc(secp256k1.sigLen)
      if (
        secp256k1.s._secp256k1_ecdsa_recoverable_signature_convert(
          secp256k1.ctx,
          sig,
          rawSig
        ) !== 1
      ) {
        secp256k1.s._free(rawSig)
        secp256k1.s._free(sig)
        return false
      }
      secp256k1.s._free(rawSig)

      // encode as DER
      let der = secp256k1.s._malloc(74)
      let derLength = 74
      if (
        secp256k1.s._secp256k1_ecdsa_signature_serialize_der(
          secp256k1.ctx,
          der,
          derLength,
          sig
        ) !== 1
      ) {
        secp256k1.s._free(sig)
        secp256k1.s._free(der)
        return false
      }
      secp256k1.s._free(sig)

      let derb = secp256k1.copyToBuffer(der, derLength)
      secp256k1.s._free(der)

      return derb
    }

    secp256k1._privkeyToPubkey = function(privkeyBuf) {
      if (
        isBuffer(privkeyBuf) !== true ||
        privkeyBuf.length !== secp256k1.msgLen
      ) {
        return false
      }
      // verify private key
      let privkey = secp256k1.s._malloc(secp256k1.privkeyLen)
      let pubkey = secp256k1.s._malloc(secp256k1.pubkeyLen)
      secp256k1.s.HEAP8.set(privkeyBuf, privkey)
      if (
        secp256k1.s._secp256k1_ec_seckey_verify(secp256k1.ctx, privkey) !== 1
      ) {
        secp256k1.s._free(privkey)
        secp256k1.s._free(pubkey)
        return false
      }
      if (
        secp256k1.s._secp256k1_ec_pubkey_create(
          secp256k1.ctx,
          pubkey,
          privkey
        ) !== 1
      ) {
        secp256k1.s._free(privkey)
        secp256k1.s._free(pubkey)
        return false
      }
      let pb = secp256k1.copyToBuffer(pubkey, secp256k1.pubkeyLen)
      return pb
    }

    secp256k1._serializePubkey = function(pubkeyBuf, compressed) {
      let pubkey = secp256k1.s._malloc(pubkeyBuf.length)
      let outputLen = secp256k1.s._malloc(1)
      let pubLen = compressed ? 33 : 65
      let spubkey = secp256k1.s._malloc(pubLen)
      secp256k1.s.HEAP8.set(pubkeyBuf, pubkey)
      secp256k1.s.HEAP8.set([pubkeyBuf.length], outputLen)
      secp256k1.s.HEAP8.set([pubLen], outputLen)
      if (
        secp256k1.s._secp256k1_ec_pubkey_serialize(
          secp256k1.ctx,
          spubkey,
          outputLen,
          pubkey,
          compressed
            ? secp256k1.SECP256K1_EC_COMPRESSED
            : secp256k1.SECP256K1_EC_UNCOMPRESSED
        ) !== 1
      ) {
        secp256k1.s._free(pubkey)
        secp256k1.s._free(outputLen)
        secp256k1.s._free(spubkey)
        return false
      }
      let pc = secp256k1.copyToBuffer(spubkey, pubLen)
      secp256k1.s._free(pubkey)
      secp256k1.s._free(outputLen)
      secp256k1.s._free(spubkey)
      return pc
    }
  })

  return secp256k1
}
