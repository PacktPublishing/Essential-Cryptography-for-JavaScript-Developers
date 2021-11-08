// Import the required modules
const crypto = require('crypto')

// Promisify the randomBytes method
const randomBytes = require('util').promisify(crypto.randomBytes)

/**
 * Encrypts a stream using the given key, using AES-256-GCM.
 * @param {Buffer} key The 256-bit key used to encrypt the message
 * @param {import('stream').Readable} source Readable stream to the input (plaintext)
 * @param {import('stream').Writable} destination Writable stream to the destination, where the output (ciphertext) will be written
 * @returns {Promise<Buffer>} The authentication tag for the ciphertext
 */
async function encrypt(key, source, destination) {
    // Generate a random IV
    // This is 12-byte for AES-GCM
    const iv = await randomBytes(12)

    // Need to wrap this into a Promise to await on the completion of the stream
    return new Promise((resolve, reject) => {
        // Create a Cipher object
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)

        // Listen to when the encryption is done
        cipher.on('end', () => {
            // Resolve the Promise and return the authentication tag
            const tag = cipher.getAuthTag()
            resolve(tag)
        })

        // Handle errors
        cipher.on('error', (err) => {
            // Reject the Promise to return the error
            reject(err)
        })

        // In the destination stream, write the IV first
        destination.write(iv)

        // Then, use pipes to read from the input stream, pipe through the cipher,
        // then write to the output stream
        source.pipe(cipher).pipe(destination)
    })
}

/**
 * Decrypts the encrypted stream using the given key
 * It also checks the stream's integrity using the authentication tag
 * @param {Buffer} key The 256-bit key used to encrypt the message
 * @param {Buffer} tag The authentication tag for this ciphertext
 * @param {import('stream').Readable} source Readable stream to the input (ciphertext)
 * @param {import('stream').Writable} destination Writable stream to the destination, where the output (plaintext) will be written
 * @returns {Promise<void>} Promise that resolves with no value once the work is done
 */
async function decrypt(key, tag, source, destination) {
    // Read the first 12 bytes from the encrypted stream, which are the IV
    // Need to wrap this into a Promise to await on data to be available
    const iv = await new Promise((resolve) => {
        const cb = () => {
            const iv = source.read(12)
            source.off('readable', cb)
            return resolve(iv)
        }
        source.on('readable', cb)
    })
    if (!iv) {
        throw Error('iv is null')
    }

    // Need to wrap this into a Promise to await on the completion of the stream
    return new Promise((resolve, reject) => {
        // Create a Decipher object and set the authentication tag
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
        decipher.setAuthTag(tag)

        // Listen to when the encryption is done
        decipher.on('end', () => {
            // Resolve the Promise with no value
            resolve()
        })

        // Handle errors
        decipher.on('error', (err) => {
            // Reject the Promise to return the error
            reject(err)
        })

        // Use pipes to read the encrypted stream, decrypt it,
        // then write the result to stream
        source.pipe(decipher).pipe(destination)
    })
}

/* Example usage */

const fs = require('fs')
const {Buffer} = require('buffer')

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async function() {
    // In this case, we're using a pre-shared key
    // The key is stored here base64-encoded, so we need to decode it
    const key = Buffer.from('P6PXZieOwqXRRFuYd02MlJYpPAW7rbn5lE2q1Ke259I', 'base64')

    // Path of the test file
    const testFile = '../test-files/alessandro-porri-yl4y4l86gEk-unsplash.jpg'

    // Encrypt the file testFile into testFile+'.enc'
    // Returns the AES-GCM authentication tag
    let tag
    {
        // Get streams to the input and output files
        // Input = plaintext
        // Output = encrypted
        const inFile = fs.createReadStream(testFile)
        const outFile = fs.createWriteStream(testFile + '.enc')
        tag = await encrypt(key, inFile, outFile)
        console.log('File was encrypted; authentication tag:', tag.toString('base64'))
    }

    // Decrypt the encrypted file back into testFile+'.orig'
    // Throws an exception if the decryption fails (such as if the tag doesn't match)
    {
        // Get streams to the input and output files
        // Input = encrypted
        // Output = plaintext
        const inFile = fs.createReadStream(testFile + '.enc')
        const outFile = fs.createWriteStream(testFile + '.orig')
        await decrypt(key, tag, inFile, outFile)
        console.log('File was decrypted successfully')
    }
})()

/*
Example result (will be different every time):
  File was encrypted; authentication tag: JDvEtuCLrM8USF+KvftHZA==
  File was decrypted successfully
*/
