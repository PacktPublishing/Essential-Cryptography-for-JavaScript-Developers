// Import the required modules
const crypto = require('crypto')
const fs = require('fs')
const util = require('util')

// Promisify the fs.readFile and crypto.randomBytes methods
const readFile = util.promisify(fs.readFile)
const randomBytes = util.promisify(crypto.randomBytes)

/**
 * Encrypts a message using hybrid encryption (RSA+AES) and the given public key.
 * Returns an object containing the encrypted message as well as the wrapped (encrypted) symmetric key.
 * @param {crypto.KeyObject} publicKey Public key object
 * @param {string} plaintext The message to encrypt, as a string
 * @returns { Promise<{encrypted: Buffer, wrappedKey: Buffer}> } Object containing the encrypted message as well as the wrapped key
 */
async function hybridEncrypt(publicKey, plaintext) {
    // Generate a new symmetric key as a random sequence of bytes
    // Because we're using AES-256 in this example, we need a 256-bit (32-byte) sequence
    const symmetricKey = await randomBytes(32)

    // Encrypt the message using the symmetric key
    const encrypted = await symmetricEncrypt(symmetricKey, plaintext)

    // Wrap (encrypt) the symmetric key using RSA and the public key
    const wrappedKey = rsaEncrypt(publicKey, symmetricKey)

    // Return an object with the encrypted message and the wrapped key
    return {encrypted, wrappedKey}
}

/**
 * Decrypts an encrypted message using hybrid encryption (RSA+AES) and a symmetric key encrypted with a RSA key.
 * @param {crypto.KeyObject} privateKey Private key object
 * @param {Buffer} wrappedKey Wrapped symmetric key
 * @param {Buffer} message The encrypted message
 * @returns {string} The decrypted message
 */
function hybridDecrypt(privateKey, wrappedKey, message) {
    // Unwrap (decrypt) the symmetric key using RSA and the private key
    const symmetricKey = rsaDecrypt(privateKey, wrappedKey)

    // Decrypt the message using the symmetric key
    const decrypted = symmetricDecrypt(symmetricKey, message)

    // Return the decrypted message as a string
    return decrypted.toString('utf8')
}

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async function() {
    // Message to encrypt
    const plaintext = 'Hello world!'

    // Load the public and private keys
    // The public one is used for encrypting the message (in this case, to encrypt a symmetric key) and the private one is using for decryption
    const publicKeyObject = crypto.createPublicKey(
        await readFile('public.pem')
    )
    const privateKeyObject = crypto.createPrivateKey(
        await readFile('private.pem')
    )

    // Encrypt the message using hybrid encryption, and obtain both the ciphertext (encrypted message) and the wrapped key (encrypted key)
    const {wrappedKey, encrypted} = await hybridEncrypt(publicKeyObject, plaintext)

    // You will need to transmit to the other party both the ciphertext and the wrapped key
    // Showing them here encoded as base64
    console.log('Encrypted message and wrapped key', {
        encrypted: encrypted.toString('base64'),
        wrappedKey: wrappedKey.toString('base64'),
    })

    // Decrypt the encrypted message using the private key and the wrapped key
    const decrypted = hybridDecrypt(privateKeyObject, wrappedKey, encrypted)

    // Show the result
    console.log('Decrypted message:', decrypted.toString('utf8'))
})()

/*** From rsa-encrypt.js ***/

function rsaEncrypt(publicKey, plaintext) {
    return crypto.publicEncrypt(
        {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        plaintext
    )
}
function rsaDecrypt(privateKey, message) {
    return crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        message
    )
}

/*** Example symmetric encryption/decryption functions from ch4/symmetric-encryption/aes-256-gcm.js ***/

async function symmetricEncrypt(key, plaintext) {
    const iv = await randomBytes(12)
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
    const encrypted = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final()
    ])
    const tag = cipher.getAuthTag()
    return Buffer.concat([iv, tag, encrypted])
}

function symmetricDecrypt(key, message) {
    const iv = message.slice(0, 12)
    const tag = message.slice(12, 28)
    const ciphertext = message.slice(28)
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAuthTag(tag)
    const decrypted = Buffer.concat([
        decipher.update(ciphertext, 'utf8'),
        decipher.final()
    ])
    return decrypted.toString('utf8')
}

/*
Example result (will be different every time):
  Encrypted message and wrapped key {
    encrypted: 'ing7W+vRoLDhu6FO6xlnBRxS/f01WF+R+O6gvidRZRCE9dlQ7VKdfA==',
    wrappedKey: 'NT0KMsfTs9TdcyYKDvMysU3cttlmUe8CU3KsyIq810ERC1GUHPha5hu5syNEgv0jvJh+6yT8PR1eggzRygGi0+JgtDoJN0pPqtWTaqoSVXa0V5uXXuyQSabOUdiTARPWv8CADRAUNQhGQn0mnvpaGttqXd1OacbyEMK0kAilsKwrIt5BGuOuQMXTa9XKnFGCtNEOMNgOYSH1Djk1Z4kGcfaHMlPcY0ex83s2sxhpYusuwR7boHoWAK4eIbZvszMwZT0R39nAodplcabQdZOJ4NCz+LlBbQNAtMxxzjeXE5eKubHTJYAtS4rh9G8xjhGiQDlgOPcJahScobEQVOqU/iS2pncdhr6Fmjfxxgc5FT1S08onVz/vkBf3ExG0TYWiLamM9ED9ZPUkvdtNjJrmQ0URfrFkTjcvngKVUfQndaiV5RQtA2ms7i6hxr0AqqNDiXIEyg6CTNHrNzDkaDoq/3/Cklnja6PEpm29HfxyZ++eFSUomftZRtUYDxjw+gYZ4l6ms3wcGVWxyvFD71+l/KZO/EbtmOPpBdLpAuuRZfkesT/gCwwrBrgm88uFXvEECIMJHxrV2pAMPPkV9kQmAttSwlEGK7QRUmburvw7x2WsUCVJGDYKLq2OcrctoW8LM+CeteGk57cDzis/vt3Yv2eNKw7hzo06ClS9J8ztSwk='
  }
  Decrypted message: Hello world!
*/
