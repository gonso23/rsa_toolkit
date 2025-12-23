# RSA Encryption & Signing Toolkit

## Security
**Encryption:** RSA-OAEP-SHA256 + AES-256-CBC  
**Signing:**    RSA-PSS-SHA256 (modern digital signatures)  
**Security:**   2048-bit RSA (current standard), 256-bit AES (military grade)

## Generate Keys
python rsaTK.py --generate-keys myKey
python rsaTK.py -k 4096 -gk mySecKey

**Output:** `myKey_private_key.pem` (SECRET!) + `myKey_public_key.pem` (share!)

## Text 
RSA only, max ~190 bytes

### Encrypt short text
python rsaTK.py myKey -et "Secret message"

### Decrypt short text
python rsaTK.py myKey -dt "BASE64_STRING"

### Sign short text
python rsaTK.py myKey -st "Important message"

### Verify short text
python rsaTK.py other_pubkey -vt "Important message" "BASE64_SIGNATURE"

## Long Text 
AES+RSA hybrid, unlimited size

### Encrypt long text
python rsaTK.py myKey -el "Very long message..."

### Decrypt long text
python rsaTK.py myKey -dl "BASE64_HYBRID_STRING"

## Files 
AES+RSA hybrid, unlimited size
### Encrypt file
python rsaTK.py myKey -ef budget.xlsx

**Output:** `budget.xlsx.encrypted`

### Decrypt file
python rsaTK.py myKey -df `budget.xlsx.encrypted`

##Signatures
Algorithm: RSA-PSS + SHA256
Text: Direct RSA-PSS signature (copy-paste format)
Files: SHA256 file hash → RSA-PSS signature → .sig file
Private key signs → Public key verifies
Security: PSS padding (modern, collision-resistant) + SHA256

###Sign file
python rsaTK.py myKey -sf document.pdf
**Output:** document.pdf.sig

###Verify file
python rsaTK.py other_pubkey -vf document.pdf document.pdf.sig
**Output:** Signature VALID or Signature INVALID
