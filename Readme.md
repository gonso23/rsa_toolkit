# RSA Encryption Toolkit

## Security
**Used algorithms:** RSA-OAEP-SHA256 + AES-256-CBC  
**Security:** 2048-bit RSA (current standard), 256-bit AES (military grade)

## Generate Keys
python rsaTK.py --generate-keys myKey
python rsaTK.py -k 4096 -gk mySecKey

**Output:** `myKey_private_key.pem` (SECRET!) + `myKey_public_key.pem` (share!)

## Text (RSA only)
**Max size:** ~190 bytes (2048-bit) / ~380 bytes (4096-bit)

### Encrypt short text
python rsaTK.py myKey -et "Secret message"

### Decrypt short text
python rsaTK.py myKey -dt "JmUUa4aPeuDf/.../klsPk6yGiIrnmcZDtxw=="


## Long Text (AES+RSA hybrid, unlimited size)
### Encrypt long text
python rsaTK.py myKey -el "This is a very long message that exceeds RSA limits..."

### Decrypt long text
python rsaTK.py myKey -dl "JmUUa4aPeuDf/.../klsPk6yGiIrnmcZDtxw=="

## Files (AES+RSA hybrid, unlimited size)
### Encrypt file
python rsaTK.py myKey -ef budget.xlsx

### Decrypt file
python rsaTK.py myKey -df budget.xlsx.encrypted
