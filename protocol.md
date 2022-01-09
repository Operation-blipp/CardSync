

```
UserEncryptedRecord = {
    "CardSync_Version": String - Version string, Current version: "0.1.0"
    "PayloadEncryptionType": enum describing symmetric key cipher used in encrypting payload. Currently supported ciphers: AES_CBC_16_16
    "KeyEncryptionType": String - enum describing public key encryption type. Currently supported public keys: RSA2048
    "EncryptedKey": Base64-encoded key used in symmetric cipher. Keyformat depends on PayloadEncryptionType.
    "EncryptedPayload": Base64-encoded "UserPayload" encrypted with the chosen symmetric cipher and key. 
}
```
```
UserPayload = {
    "IdentificationType": String - Signifies the type of identification used to verify the user. Currently supported: "PasswordHash"
    "IdentificationData": Object with structure corresponding to the identification type. 
    "DirectiveName": String - Signifies the directive to be executed. Currenlty supported directives: getLatest, uploadCard, unlockCard, Login.
    "DirectiveArguments": Object with structure corresponding to the DirectiveName
}
```
```
identificationdata_PasswordHash = {
    "HashAlgorithm": String - Signifies the hash algorithm used. Currenlty supported algorithms: "SHA256"
    "UserName": String - Username string
    "PasswordHash": String - hex-encoded hash of the password.
}
```

```
ServerEncryptedRecord = {
  "EncryptionStatus" : String - Status of Encryption. "OK" or some error message.
  "EncryptedPayload" : Base64-encoded "ServerPayload" encrypted with the chosen symmetric cipher and key. 
}
```

```
ServerPayload = {
    "StatusCode": String - Statusmessage. "OK" or some error message.
    "DirectiveResponse": Object with structure corresponding to the Directive
}
```

## Directives


Login:
    -

Verifies login with provided identifications. Doesn't include additional fields.
```
uploadCard:
    "CardData": Base64 encoded card data. 
    "Namespace": String - Optional namespace flag. Defaults to no namespace.
```
Uploads card to server.
```
getLatest:
    "CardUID": String - Hex-encoded Card UID.  
    "Namespace": String - Optional namespace flag. Defaults to no namespace.
```
Downloads card from server.
```
unlockCard:
    "CardUID": String - Hex-encoded Card UID.
    "Namespace": String - Optional namespace flag. Defaults to no namespace.
```
Unlocks card for logged in user.