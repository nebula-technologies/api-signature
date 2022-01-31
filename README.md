# API Signature
A library for making API Signatures more schematic and reducing implementation overhead. The library helps build the desired API signing structure and ensures the validation will be done the same way across every service that uses the following library.

## Prolog
Many systems today are using Logins and API-key to secure public APIs. Unfortunately, this is not true; when a user is authorized, the system sends an authorization token between the client and the server. If these tokens get hijacked, the malicious attacker can then parse payloads on behalf of the valid user.
An API signature can help alleviate this problem.


## Nonce
A nonce is a single-use ID that continuously increases, meaning one can never use the same ID again, and it needs always to be greater than the last. This ID is bound to the current API key and used to obscure the information sent between the server and the client.

### Nonce a Lockdown security system
If an invalid nonce gets used, the API key should be blocked, and the system must require either a new API key created or the user must unblock the key.
Nonce will secure the system by making sure an attack will be denied sending a falsified payload, and in case someone successfully tries to do it, there is a high chance that the application that initially was using the API key will end up blocking it.

### Example
> The attacker will likely use a large number as the nonce, causing the other client to send a lower number and get denied - blocking the key.
At this point, the Hijacked tokens are no longer valid for use, and further illicit use will get denied.

##Usage

### Defining an API structure
An API Structure can either be generated programatically or be imported from a configuration file.
There are multiple available manipulators for the signing available:
| Manipulator | Function | Description |
| --- | --- | ---|
| HMAC SHA256 | HmacSha256(Box<SignCal>, Box<SignCal>) | This will create a SHA256 using the HMAC[^1] |
| HMAC SHA512 | HmacSha512(Box<SignCal>, Box<SignCal>) |  |
| SHA256 | Sha256(Box<SignCal>) | |
| SHA512 | Sha512(Box<SignCal>) | |
| Base64 Encoder | Base64Encode(Box<SignCal>) | |
| Base64 Decoder | Base64Decode(Box<SignCal>) | |
| Base58 Encoder | Base58Encode(Box<SignCal>) | |
| Base58 Decoder | Base58Decode(Box<SignCal>) | |
| Data Appending | Append(Vec<SignCal>) | |
| Data Variable from Raw| VarData(String) | |
| Data Variable from String| VarString(String) | |
| Data Variable from Integer| VarInteger(String) | | 
| Raw Data | Raw(Vec<u8>) | |

[^1]: HMAC: Hash-Based Message Authentication Codes
