// Import the axios module to make HTTP requests
// https://www.npmjs.com/package/axios
const axios = require('axios').default

// Import the required modules
const crypto = require('crypto')

// Promisify the crypto.generateKeyPair method
const generateKeyPair = require('util').promisify(crypto.generateKeyPair)

// URL where the server is listening on
const serverUrl = 'http://localhost:3000'

// Need to wrap this in an immediately-invoked function expression (IIFE) because of async code
;(async function() {
    // Begin the key agreement by requesting the server's public key
    let publicKeyRes = await axios.get(serverUrl + '/public-key')
    const serverKey = publicKeyRes.data

    // Generate a new x25519 key for this client
    // Then export the public key as PEM
    const clientKeyPair = await generateKeyPair('x25519')
    const clientPublicKeyPem = clientKeyPair.publicKey.export({
        type: 'spki',
        format: 'pem'
    })

    // Calculate the shared secret
    const sharedSecret = crypto.diffieHellman({
        publicKey: crypto.createPublicKey(serverKey.publicKey),
        privateKey: clientKeyPair.privateKey
    })

    // Submit our (the client's) public key to the server, so the server can generate the same shared secret
    await axios.post(serverUrl + '/key-agreement', {
        serverKeyId: serverKey.keyId,
        publicKey: clientPublicKeyPem
    })

    // Print the shared secret; it should be the same on the server
    console.log('The shared secret is', sharedSecret.toString('hex'))
})()
