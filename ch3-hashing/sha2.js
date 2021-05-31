// Import the crypto library
const crypto = require('crypto')

/**
 * Calculates the SHA-256 digest of a message.
 * @param {string|Buffer|crypto.BinaryLike} message Message to hash
 * @param {'hex'|'base64'|'base64url'} [encoding] Optional encoding to stringify the result in
 * @returns {Buffer|string} The SHA-256 digest of the message. Result is a Buffer if encoding is empty; otherwise, it's a string encoded in the specified encoding.
 */
function sha256Digest(message, encoding) {
    return crypto.createHash('sha256')
        .update(message)
        .digest(encoding)
}

/* Example usage */

console.log(sha256Digest('Hello world!'))
console.log(sha256Digest('Hello world!', 'hex'))
console.log(sha256Digest('Hello world!', 'base64'))
