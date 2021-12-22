// This is an example of using the playground
// It demonstrates encoding a message to base64

// You can import modules from NPM, such as this ArrayBuffer encoding/decoding library
import {Encode} from 'arraybuffer-encoding/base64/standard'

// Wrap the code in an asynchronous IIFE to use the await keyword
;(async () => {
    // Encode a string to Base64
    const message = 'Hello CodeSwing!'
    const encoder = new TextEncoder()
    const encoded = Encode(encoder.encode(message))

    // Print the result
    console.log(message, encoded)
})()
