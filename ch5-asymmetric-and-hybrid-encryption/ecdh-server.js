// Import the express module to create a web server
// https://www.npmjs.com/package/express
// Note: requires express 4.16+
const express = require('express')

// Import the required modules
const crypto = require('crypto')

// Promisify the crypto.generateKeyPair method
const generateKeyPair = require('util').promisify(crypto.generateKeyPair)

// Dictionary that stores all ephemeral private keys used for the ECDH key agreement
// We're keeping the keys in memory just for this example in production, you will probably want to store the keys in a database and purge private keys after a certain amount of time, whether the key agreement was completed or not
const keyPairs = {}

// Create a web server using Express
const app = express()

// Handler for GET /public-key
// This generates a new key pair, saves the private key in memory and returns the public part to the client
app.get('/public-key', async (req, res) => {
    // Generate a new x25519 key pair
    const newKeyPair = await generateKeyPair('x25519')
    // Export the public key encoded as PEM
    const publicKey = newKeyPair.publicKey.export({
        type: 'spki',
        format: 'pem'
    })
    // Calculate a "key ID", which in this simplified scenario is just the SHA-256 hash of the PEM-encoded public key
    const keyId = crypto.createHash('sha256')
        .update(publicKey)
        .digest('base64url')
    // Store the key pair in the dictionary, as we'll need the private key to complete the key agreement
    keyPairs[keyId] = newKeyPair
    // Return the (PEM-encoded) public key to the client and the key ID
    res.send({
        keyId,
        publicKey
    })
})

// Handler for POST /key-agreement
// This receives the client's public key (publicKey) and the ID of the private key the server (serverKeyId) generated in the /public-key step
// It uses those parameters to complete the ECDH key agreement and generate the shared secret
// This request expects input in JSON format in the POST body
app.post('/key-agreement', express.json(), (req, res) => {
    // Get the client's public key from the input
    const clientPublicKey = req.body.publicKey
    if (!clientPublicKey) {
        throw Error(`Missing parameter 'publicKey'`)
    }
    // Get the server's key ID from the input
    const keyId = req.body.serverKeyId
    if (!keyId) {
        throw Error(`Missing parameter 'serverKeyId'`)
    }
    const serverKeyPair = keyPairs[keyId]
    if (!serverKeyPair) {
        throw Error(`Key pair with ID ${keyId} not found`)
    }
    // Calculate the shared secret
    const sharedSecret = crypto.diffieHellman({
        publicKey: crypto.createPublicKey(clientPublicKey),
        privateKey: serverKeyPair.privateKey
    })
    // Remove the key from memory
    delete keyPairs[keyId]
    // Print the shared secret; it should be the same on the client
    console.log('The shared secret is', sharedSecret.toString('hex'))
    // Send an OK to the client
    res.send('OK')
})

// Start the web server, listening on port 3000
app.listen(3000, () => {
    console.log('Server listening on http://localhost:3000')
})
