// Import the crypto library
const crypto = require('crypto')

/**
 * Calculates the SHA-256 digest of a readable stream.
 * @param {import('stream').Readable} read Readable stream
 * @param {'hex'|'base64'|'base64url'} [encoding] Optional encoding to stringify the result in
 * @returns {Buffer|string} The SHA-256 digest of the message read from the stream. Result is a Buffer if encoding is empty; otherwise, it's a string encoded in the specified encoding.
 */
function sha256DigestStream(read, encoding) {
    // Need to wrap this into a Promise to await on the completion of the stream
    return new Promise((resolve, reject) => {
        // Create the object that will compute the hash
        const hash = crypto.createHash('sha256')
        // In case of error reading the stream, the promise is rejected with the error
        read.on('error', (err) => {
            // Reject the promise with the error
            reject(err)
        })
        // At the end of the stream, compute the hash
        read.on('end', () => {
            hash.end()
            // Resolve the promise with the computed value of the hash
            resolve(hash.digest(encoding))
        })
        // Pipe the message stream into the hash object
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
    // Open a file and create a readable stream to that
    const read = fs.createReadStream(path)
    // Calculate the digest of teh stream
    const digest = await sha256DigestStream(read, 'hex')
    console.log(digest)
}
hashFile('../test-files/alessandro-porri-yl4y4l86gEk-unsplash.jpg')
