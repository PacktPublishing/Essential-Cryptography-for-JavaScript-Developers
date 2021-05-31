// Import the required modules
const crypto = require('crypto')

// Promisify the randomBytes method
const randomBytes = require('util').promisify(crypto.randomBytes)

/**
 * Encrypts the plaintext message using the given key with AES-256-CBC
 * @param {Buffer} key A 256-bit key
 * @param {string} plaintext The message to encrypt, as a string
 * @returns {Buffer} The ciphertext (with the IV prepended)
 */
async function encrypt(key, plaintext) {
    // Generate a random IV
    // This is 16-byte for AES-CBC
    const iv = await randomBytes(16)

    // Encrypt the message
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
    const encrypted = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final()
    ])

    // Prepend the IV to the ciphertext
    // This is the data that should be stored or transmitted
    return Buffer.concat([iv, encrypted])
}

/**
 * Decrypts the encrypted message using the given key with AES-256-CBC
 * @param {Buffer} key The 256-bit key used to encrypt the message
 * @param {Buffer} message The ciphertext (with the IV prepended)
 * @returns {string} The decrypted message
 */
function decrypt(key, message) {
    // The first 16 bytes in the encrypted message are the IV, so we need to extract them
    const iv = message.slice(0, 16)
    const ciphertext = message.slice(16)

    // Decrypt the ciphertext
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv)
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
  Key: sicpvpQxtKyJbxleC3nTcB39cAVCgx/f2r3Ut4Fmp/g=
  Encrypted message: QZIptzlPQdX941xU5Qhef2ZGBH06vvPeSuxTn/usACE=
  Decrypted message: Hello world!
*/
