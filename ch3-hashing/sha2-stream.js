// Import the crypto library
const crypto = require('crypto')

/**
 * Calculates the SHA-256 digest of a readable stream.
 * @param {import('stream').Readable} read Readable stream
 * @param {'hex'|'base64'|'base64url'} [encoding] Optional encoding to stringify the result in
 * @returns {Buffer|string} The SHA-256 digest of the message read from the stream. Result is a Buffer if encoding is empty; otherwise, it's a string encoded in the specified encoding.
 */
function sha256DigestStream(read, encoding) {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash('sha256')
        read.on('error', (err) => {
            reject(err)
        })
        read.on('end', () => {
            resolve(hash.digest(encoding))
        })
        read.pipe(hash)
    })
}

/* Example usage */

const fs = require('fs')
/**
 * Calculates the SHA-256 file of a file from disk and prints it encoded as hex.
 * @param {string} path Path to the file to hash
 */
async function hashFile(path) {
    const read = fs.createReadStream(path)
    const digest = await sha256DigestStream(read, 'hex')
    console.log(digest)
}
hashFile('../test-files/alessandro-porri-yl4y4l86gEk-unsplash.jpg')
