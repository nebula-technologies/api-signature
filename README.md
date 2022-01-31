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
| HMAC SHA256 | HmacSha256(Box\<SignCal\>\[API enctyption key\], Box\<SignCal\>\[Data\]) | This will create a SHA256 HMAC[^1] using the API key and the data  |
| HMAC SHA512 | HmacSha512(Box\<SignCal\>\[API enctyption key\], Box\<SignCal\>\[Data\]) | This will create a SHA512 HMAC[^1] using the API key and the data |
| SHA256 | Sha256(Box\<SignCal\>) | Encode data in SHA256 format |
| SHA512 | Sha512(Box\<SignCal\>) | Encode data in SHA512 format |
| Base64 Encoder | Base64Encode(Box\<SignCal\>) | Encode in Base64 format |
| Base64 Decoder | Base64Decode(Box\<SignCal\>) | Decode Base64 |
| Base58 Encoder | Base58Encode(Box\<SignCal\>) | Encode in Base58 format |
| Base58 Decoder | Base58Decode(Box\<SignCal\>) | Decode Base58 |
| Data Appending | Append(Vec\<SignCal\>) | Appending data together |
| Data Variable from Raw| VarData(String) | Each signature will be passed a set of variables, this is for defining a variable where the expected data is raw `&[u8]` |
| Data Variable from String| VarString(String) | Each signature will be passed a set of variables, this is for defining a variable where the expected data is Text `string | &str` |
| Data Variable from Integer| VarInteger(String) | Each signature will be passed a set of variables, this is for defining a variable where the expected data is Number `i32 | u32 | i64 | u64 | i128 | u128 | usize` |
| Raw Data | Raw(Vec\<u8\>) | This is not a variable, but directly inserted data. This can be used for salting by config |

[^1]: HMAC: Hash-Based Message Authentication Codes

### Configuration
In this configuration example we are using the default configuration that the library is supplying.

```rust
let config = Base64Encode(
    HmacSha512(
        Base64Decode(VarString("secret_key".to_string()).into()).into(),
        Append(vec![
            VarString("url".to_string()),
            Sha256(
                Append(vec![
                    VarInteger("nonce".to_string()),
                    VarString("payload".to_string()),
                ])
                .into(),
            ),
        ])
        .into(),
    )
    .into(),
);
```

This configuration takes 4 variables `payload`,`secret_key`, `url`, and `nonce`.
these can be set by using the signature libraries `.var([key], [data]`.

### Common usage

```rust
let nonce = 1616492376594usize;
let config = Base64Encode(
    HmacSha512(
        Base64Decode(VarString("secret_key".to_string()).into()).into(),
        Append(vec![
            VarString("url".to_string()),
            Sha256(
                Append(vec![
                    VarInteger("nonce".to_string()),
                    VarString("payload".to_string()),
                ])
                .into(),
            ),
        ])
        .into(),
    )
    .into(),
);
let mut signature = Signature::default();
signature.var("payload", format!("nonce={}&ordertype=limit&pair=XBTUSD&price=37500&type=buy&volume=1.25",nonce))
    .var("secret_key", "kQH5HW/8p1uGOVjbgWA7FunAmGO8lsSUXNsu3eow76sz84Q18fWxnyRzBHCd3pd5nE9qa99HAZtuZuj6F1huXg==")
    .var("url", "/0/private/AddOrder")
    .nonce(Arc::new(move || -> Vec<u8> {nonce.to_string().as_bytes().to_vec()}))
    .config();

let api_sign = b"4/dpxb3iT4tp/ZCVEwSnEsLxx0bqyhLpdfOpc6fn7OR8+UClSV5n9E6aSS8MPtnRfp32bAb0nmbRn6H8ndwLUQ==".to_vec();

assert_eq!(api_sign, signature.sign());
```

