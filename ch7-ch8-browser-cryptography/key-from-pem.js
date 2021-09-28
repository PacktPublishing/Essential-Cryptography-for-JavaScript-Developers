// This depends on a base64 decoding library, such as arraybuffer-encoding from NPM
import {Decode} from 'arraybuffer-encoding/base64/standard'

/**
 * Returns a CryptoKey object that contains a public or private key read from a PEM file.
 * Supports keys in PKCS#8 and SPKI formats, for private and public keys respectively.
 * @param keyType {'public'|'private'} Type of the key: public or private
 * @param pem {string} PEM-encoded key
 * @param algorithm {RsaHashedImportParams|EcKeyImportParams} Algorithm parameters
 * @param exportable {boolean} Set to true if the key can be exported
 * @param usages {Iterable<KeyUsage>} Permitted uses for the key
 * @returns {Promise<CryptoKey>} Key imported from the PEM
 * @async
 */
function keyFromPem(keyType, pem, algorithm, exportable, usages) {
    // Get the key format and the header and footer depending on the key type
    let format = ''
    let header = ''
    let footer = ''
    switch (keyType) {
        case 'public':
            format = 'spki'
            header = '-----BEGIN PUBLIC KEY-----'
            footer = '-----END PUBLIC KEY-----'
            break
        case 'private':
            format = 'pkcs8'
            header = '-----BEGIN PRIVATE KEY-----'
            footer = '-----END PRIVATE KEY-----'
            break
        default:
            throw Error('Invalid key type')
    }

    // Extract the base64-encoded block from the PEM, removing the header and footer and then removing all newlines
    // Then, decode the data from base64 to obtain the raw DER bytes
    const keyData = Decode(
        pem.trim()
            .slice(header.length, -1 * footer.length)
            .replaceAll('\n', '')
    )

    // Import the key
    // Note that this returns a Promise
    return crypto.subtle.importKey(
        format,
        keyData,
        algorithm,
        exportable,
        usages
    )
}

/* Example usage */

// Example P-256 key pair
const publicPem = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAxCMgCXKlaRKbPSzcIQX4VNcMyTc
IErMdoaOOCv3tMKIBKh769CPyfZa2KVw5REjKhi9Iw2pTBol/W1TO9T55g==
-----END PUBLIC KEY-----
`
const privatePem = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgan2KBrkOZDmOh/sK
tm18vwiLZ45uz9k35CqOir69yZShRANCAAQDEIyAJcqVpEps9LNwhBfhU1wzJNwg
Ssx2ho44K/e0wogEqHvr0I/J9lrYpXDlESMqGL0jDalMGiX9bVM71Pnm
-----END PRIVATE KEY-----
`

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async () => {
    // Parameter "algorithm" for both ECDSA keys, using the P-256 (prime256v1) curve
    const algorithm = {
        name: 'ECDSA',
        namedCurve: 'P-256'
    }

    // Import the public and private keys from PEM
    const publicKey = await keyFromPem('public', publicPem, algorithm, false, ['verify'])
    const privateKey = await keyFromPem('private', privatePem, algorithm, false, ['sign'])

    // Print the result
    console.log(publicKey)
    console.log(privateKey)
})()
