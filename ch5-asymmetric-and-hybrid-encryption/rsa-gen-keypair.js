// Import the required modules
const crypto = require('crypto')
const fs = require('fs')
const util = require('util')

// Promisify the crypto.generateKeyPair and fs.writeFile methods
const generateKeyPair = util.promisify(crypto.generateKeyPair)
const writeFile = util.promisify(fs.writeFile)

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async function() {
    // Generate a RSA new key pair, containing both private and public keys
    const keyPair = await generateKeyPair('rsa', {
        // Size of the RSA key in bits (normally 4096, 3072, or 2048)
        modulusLength: 4096,
    })

    // Export the private key as PKCS#8 encoded in a PEM block
    const privateKey = keyPair.privateKey.export({
        type: 'pkcs8',
        format: 'pem'
    })

    // Save the private key to a file called "private.pem"
    await writeFile('private.pem', privateKey)

    // Export the public key as SPKI encoded in a PEM block
    const publicKey = keyPair.publicKey.export({
        type: 'spki',
        format: 'pem'
    })

    // Save the public key to a file called "public.pem"
    await writeFile('public.pem', publicKey)
})()
