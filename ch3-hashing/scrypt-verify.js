// Import the crypto module
const crypto = require('crypto')

// Convert the scrypt method into a promisified one
const scrypt = require('util').promisify(crypto.scrypt)

/**
 * 
 * @param {string} stored The hash as retrieved from the database (which contains the salt as prefix)
 * @param {string} passphrase The passphrase to verify
 * @returns {boolean} Returns true if the passphrase matches
 */
async function scryptVerify(stored, passphrase) {
    // Decode the stored value from base64. The first 16 bytes which are the salt, the rest is the passphrase
    const saltLength = 16
    const buf = Buffer.from(stored, 'base64')
    const salt = buf.slice(0, saltLength)
    const hash = buf.slice(saltLength)

    // Calculate the hash of the passphrase with the same salt used in the stored value
    const verifyHash = await scrypt(passphrase, salt, 32)

    // Check if the hashes match
    return verifyHash.compare(hash) === 0
}

/* Example usage */

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async function() {
    // Input
    const passphrase = '<passphrase from the user>'
    const stored = '<base64-encoded value retrieved from the database>'

    // Check if the passphrase matches
    if (await scryptVerify(stored, passphrase)) {
        console.log(`Passphrases match`)
    }
    else {
        console.log(`Passphrases don't match`)
    }
})()
