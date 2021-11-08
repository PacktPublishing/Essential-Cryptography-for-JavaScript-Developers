// This depends on a hex encoding library, such as arraybuffer-encoding from NPM
import {Encode} from 'arraybuffer-encoding/hex'

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async () => {
    // Message to hash
    // Because our message is a string, we need to encode it in a Uint8Array first
    const message = (new TextEncoder()).encode('Hello world!')

    // Calculate the SHA-256 hash of the message
    const result = await window.crypto.subtle.digest(
        'SHA-256',
        message,
    )

    // Print the result, encoded as hex
    console.log(Encode(result))
})()

/*
Result:
  c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a
*/
