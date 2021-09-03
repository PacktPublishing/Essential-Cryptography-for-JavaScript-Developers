// Import the required modules
const crypto = require('crypto')
const fs = require('fs')

/**
 * Calculates the digital signature of a stream using the given RSA private key.
 * As configured, this function uses SHA-256 for hashing and RSA-PSS for padding with the default options in Node.js.
 * @param {crypto.KeyObject} privateKey Private key object
 * @param {import('stream').Readable} messageStream Message to sign
 * @returns {Buffer} The signature of the message
 */
function rsaSignStream(privateKey, messageStream) {
    // Returns a promise that resolves with the signature
    return new Promise((resolve, reject) => {
        // Create a signer with the chosen hashing algorithm; we'll use SHA-256
        const signer = crypto.createSign('sha256')
        // In case of error reading the message stream, the promise is rejected with the error
        messageStream.on('error', (err) => {
            reject(err)
        })
        // When the stream ends, compute the signature and return it
        messageStream.on('end', () => {
            // End the stream and compute the signature
            signer.end()
            const signature = signer.sign({
                // Private key used for calculating the signature
                key: privateKey,
                // Padding to use; options include:
                // - `RSA_PKCS1_PSS_PADDING` for PSS
                // - `RSA_PKCS1_PADDING` for PKCS#1 v1.5
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING
            })
            // Resolve the promise with the signature
            resolve(signature)
        })
        // Pipe the message stream into the signer object
        messageStream.pipe(signer)
    })
}

/**
 * Verifies the digital signature of a stream using the given RSA public key (corresponding to the private key which was used to generate the signature).
 * @param {crypto.KeyObject} publicKey Public key object
 * @param {import('stream').Readable} messageStream Original message that was signed, in a readable stream
 * @param {Buffer} signature The signature of the message to verify
 * @returns {boolean} Returns true if the signature is valid for the message
 */
function rsaVerifyStream(publicKey, messageStream, signature) {
    // Returns a promise that resolves with the result of the verification
    return new Promise((resolve, reject) => {
        // Create a verifier with the hashing algorithm that was used to calculate the signature
        const verifier = crypto.createVerify('sha256')
        // In case of error reading the message stream, the promise is rejected with the error
        messageStream.on('error', (err) => {
            reject(err)
        })
        // When the stream ends, verify the signature
        messageStream.on('end', () => {
            // End the stream and verify the signature
            verifier.end()
            const signatureVerified = verifier.verify(
                {
                    // Public key used to verify the signature
                    key: publicKey,
                    // Padding that was used when calculating the signature
                    padding: crypto.constants.RSA_PKCS1_PSS_PADDING
                },
                signature
            )
            // Resolve the promise with the signature
            resolve(signatureVerified)
        })
        // Pipe the message stream into the verifier object
        messageStream.pipe(verifier)
    })
}

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async function() {
    // Open a readable stream to the file we want to calculate the signature of
    const filename = 'photo.jpg'
    let read = fs.createReadStream(filename)

    // Digital signatures are calculated with a private key
    // With this we're creating a crypto.KeyObject containing the private key (loaded from file)
    const privateKeyObject = crypto.createPrivateKey(
        fs.readFileSync('private.pem')
    )

    // Calculate the signature using RSA and the private key
    const signature = await rsaSignStream(privateKeyObject, read)

    // Show the result as a base64-encoded string
    console.log(`Signature of ${filename}:`, signature.toString('base64'))

    // Re-open a new readable stream to the file
    read = fs.createReadStream(filename)

    // Load the public key from file, which we'll use to verify the signature
    const publicKeyObject = crypto.createPublicKey(
        fs.readFileSync('public.pem')
    )

    // Verify the signature
    const signatureValid = await rsaVerifyStream(publicKeyObject, read, signature)

    // Show the result
    console.log('Signature valid:', signatureValid)
})()
