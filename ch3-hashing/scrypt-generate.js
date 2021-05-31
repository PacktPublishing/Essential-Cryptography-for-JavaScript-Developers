// Import the crypto and promisify modules
const crypto = require('crypto')
const {promisify} = require('util')

// Convert crypto.scrypt and crypto.randomBytes into promisified methods
const scrypt = promisify(crypto.scrypt)
const randomBytes = promisify(crypto.randomBytes)

/**
 * Calculates the hash of a passphrase using scrypt and returns the string to store in the database.
 * @param {string} passphrase Passphrase to hash
 * @returns {string} The hashes passphrase to store in the database.
 */
async function scryptHash(passphrase) {
    // Generate a 16-byte random salt
    const saltLength = 16
    const salt = await randomBytes(saltLength)

    // Calculate the hash with scrypt
    const hash = await scrypt(passphrase, salt, 32)

    // Return the value to store in the database, which contains the salt and the hash and is encoded as base64
    const stored = Buffer.concat(
        [salt, hash]
    ).toString('base64')

    // For debug purposes only
    console.log('Hash:', hash.toString('hex'))
    console.log('Salt:', salt.toString('hex'))

    return stored
}

/* Example usage */

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async function() {
    const passphrase = 'correct horse battery staple'
    const stored = await scryptHash(passphrase)
    console.log('Store value:', stored)
})()
