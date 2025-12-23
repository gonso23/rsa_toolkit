# RSA Encryption Toolkit

## Security
**Used algorithms:** RSA-OAEP-SHA256 + AES-256-CBC  
**Security:** 2048-bit RSA (current standard), 256-bit AES (military grade)

## Generate Keys
python rsa_toolkit.py --generate-keys myKey
python rsa_toolkit.py -k 4096 -gk mySecKey

**Output:** `myKey_private_key.pem` (SECRET!) + `myKey_public_key.pem` (share!)

## Text (RSA only)
**Max size:** ~190 bytes (2048-bit) / ~380 bytes (4096-bit)

### Encrypt short text
python rsa_toolkit.py myKey -et "Secret message"

### Decrypt short text
python rsa_toolkit.py myKey -dt "JmUUa4aPeuDf/.../klsPk6yGiIrnmcZDtxw=="


## Long Text (AES+RSA hybrid, unlimited size)
### Encrypt long text
python rsa_toolkit.py myKey -el "This is a very long message that exceeds RSA limits..."

### Decrypt long text
python rsa_toolkit.py myKey -dl "JmUUa4aPeuDf/.../klsPk6yGiIrnmcZDtxw=="

## Files (AES+RSA hybrid, unlimited size)
### Encrypt file
python rsa_toolkit.py myKey -ef budget.xlsx

### Decrypt file
python rsa_toolkit.py myKey -df budget.xlsx.encrypted
