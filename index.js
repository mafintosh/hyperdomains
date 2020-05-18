const hypertrie = require('hypertrie')
const sodium = require('hypercore-crypto/sodium')

module.exports = class HyperDomains {
  constructor (storage, key, opts) {
    this.trie = hypertrie(storage, key, opts)
  }

  ready (cb) {
    this.trie.ready(cb)
  }

  get discoveryKey () {
    return this.trie.discoveryKey
  }

  get key () {
    return this.trie.key
  }

  replicate (...opts) {
    return this.trie.replicate(...opts)
  }

  lookup (name, cb) {
    this.trie.get(hashDomain(name).toString('hex'), function (err, node) {
      if (err) return cb(err)
      if (!node) return cb(null, null)

      const secret = hashSecretKey(name)
      const nonce = node.value.slice(0, sodium.crypto_secretbox_NONCEBYTES)
      const key = Buffer.alloc(32)

      if (sodium.crypto_secretbox_open_easy(key, node.value.slice(nonce.length), nonce, secret)) {
        return cb(null, key)
      }

      cb(null, null)
    })
  }

  register (name, key, cb) {
    if (key.length !== 32) throw new Error('Key must be 32 bytes long')

    const secret = hashSecretKey(name)
    const value = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES + 32 + sodium.crypto_secretbox_MACBYTES)
    const nonce = value.slice(0, sodium.crypto_secretbox_NONCEBYTES)

    sodium.randombytes_buf(nonce)
    sodium.crypto_secretbox_easy(value.slice(nonce.length), key, nonce, secret)

    this.trie.put(hashDomain(name).toString('hex'), value, {
      condition (oldNode, newNode, done) {
        if (oldNode) return done(new Error('Name already registered'), false)
        done(null, true)
      }
    }, function (err, node) {
      if (err) return cb(err)
      cb(null)
    })
  }
}

function hashSecretKey (name) {
  const out = Buffer.alloc(32)
  sodium.crypto_generichash(out, Buffer.from('secret key\n' + name))
  return out
}


function hashDomain (name) {
  const out = Buffer.alloc(32)
  sodium.crypto_generichash(out, Buffer.from('domain\n' + name))
  return out
}
