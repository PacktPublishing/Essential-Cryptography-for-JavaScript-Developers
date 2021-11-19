// Import the argon2 module
// https://www.npmjs.com/package/argon2
const argon2 = require('argon2')

/**
 * Derive a key from a given passphrase and salt, using Argon2 with explicit parameters.
 * @param {string} passphrase The passphrase to derive the key from
 * @param {Buffer} salt The salt used for this key; should be 16-byte long
 * @param {number} length Number of bytes to return from the hash (should be 16 for a 128-bit key or 32 for a 256-bit key)
 * @returns {Promise<Buffer>} The symmetric key derived with Argon2
 */
async function deriveKey(passphrase, salt, length) {
    try {
        // Parameters for argon2
        const params = {
            // Set to return the raw bytes and not a base64-encoded hash (as we'd use for passwords instead)
            raw: true,
            // Key length
            hashLength: length,
            // Pass the salt
            salt: salt,
            // We need to make them all parameters explicit just in case the default ones in the library changed.
            // In fact, if that happened, the same passphrase and salt would return a different key and we wouldn't be able to decrypt our data encrypted with that key and salt combination.
            // You can tweak these as needed.
            type: argon2.argon2id,
            timeCost: 3,
            memoryCost: 4096,
            parallelism: 1,
            version: 0x13,
        }
        // Derive and return the key
        const result = await argon2.hash(passphrase, params)
        return result
    }
    catch (err) {
        console.error('An internal error occurred: ', err)
    }
}

/* Example usage */

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async function() {
    // Passphrase to use
    const passphrase = 'correct horse battery staple'

    // Salt: this should ideally be different for every file and stored together with the encrypted file
    // Recommended length is 16 bytes
    // Here it's hardcoded for our example, and it's base64-encoded so we need to decode it
    const salt = Buffer.from('WiHmGLjgzYESy3eAW45W0Q==', 'base64')

    // Derive a 128-bit key (16 bytes in length)
    const key128 = await deriveKey(passphrase, salt, 16)
    console.log('128-bit key:', key128.toString('base64'))

    // Derive a 256-bit key (32 bytes in length)
    const key256 = await deriveKey(passphrase, salt, 32)
    console.log('256-bit key:', key256.toString('base64'))
})()

/*
Result:
  128-bit key: McvSLprU4zfh1kcVOeR40g==
  256-bit key: oQumof86t+UlE6yBPCbblO6IcPmrL8qHj/jucYIxJFw=
*/
