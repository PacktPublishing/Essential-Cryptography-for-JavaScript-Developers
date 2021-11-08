// Import the required modules
const crypto = require('crypto')

// Promisify the randomBytes method
const randomBytes = require('util').promisify(crypto.randomBytes)

/**
 * Encrypts the plaintext message using the given key with AES-256-GCM
 * @param {Buffer} key A 256-bit key
 * @param {string} plaintext The message to encrypt, as a string
 * @returns {Promise<Buffer>} The ciphertext (with the IV and authentication tag prepended)
 */
async function encrypt(key, plaintext) {
    // Generate a random IV
    // This is 12-byte for AES-GCM
    const iv = await randomBytes(12)

    // Encrypt the message
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
    const encrypted = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final()
    ])

    // Prepend the IV and the authentication tag to the ciphertext
    // This is the data that should be stored or transmitted
    const tag = cipher.getAuthTag()
    return Buffer.concat([iv, tag, encrypted])
}

/**
 * Decrypts the encrypted message using the given key with AES-256-GCM
 * @param {Buffer} key The 256-bit key used to encrypt the message
 * @param {Buffer} message The ciphertext (with the IV and authentication tag prepended)
 * @returns {string} The decrypted message
 */
function decrypt(key, message) {
    // The first 12 bytes in the encrypted message are the IV
    // Next 16 bytes are the authentication tag
    // The rest is the ciphertext
    const iv = message.slice(0, 12)
    const tag = message.slice(12, 28)
    const ciphertext = message.slice(28)

    // Decrypt the ciphertext
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAuthTag(tag)
    const decrypted = Buffer.concat([
        decipher.update(ciphertext, 'utf8'),
        decipher.final()
    ])

    return decrypted.toString('utf8')
}

/* Example usage */

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async () => {
    // Message to encrypt
    const plaintext = 'Hello world!'

    // Key to use
    // In this case, we're generating a random 256-bit (32 byte) key
    // We're printing the key (base64-encoded) as example
    const key = await randomBytes(32)
    console.log('Key:', key.toString('base64'))

    // Encrypt the message and show the result (base64-encoded)
    const encrypted = await encrypt(key, plaintext)
    console.log('Encrypted message:', encrypted.toString('base64'))

    // Decrypt the encrypted message and show the result
    const decrypted = decrypt(key, encrypted)
    console.log('Decrypted message:', decrypted)
})()

/*
Example result (will be different every time):
  Key: pG0P+/xXa6nFWG+X9WcAO4uIBWCTViSEIyiZBc9JyJA=
  Encrypted message: Ab/Rr9FSkn69HxOU96we7DNNM7ntSChfVWyRXjvburtXVRa+Pvienw==
  Decrypted message: Hello world!
*/
