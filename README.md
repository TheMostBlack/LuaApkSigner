# LuaApkSigner
An APK V1 Signing Tool Implemented in C Using OpenSSL and libzip Libraries, with Lua Bindings

## Example Usage:

```lua
local LuaApkSigner = require("LuaApkSigner")

-- Generate a MANIFEST.MF file for apkPath and write it to manifestPath
LuaApkSigner.generate_manifest(apkPath, manifestPath)

-- Generate a CERT.SF file for manifestPath and write it to certPath
LuaApkSigner.generate_cert_sf(manifestPath, certPath)

-- Convert pk8Path to PEM format and write it to pemPath
LuaApkSigner.convert_pk8_to_pem(pk8Path, pemPath)

-- Generate a CERT.RSA file for certPath and write it to rsaPath, the second parameter is the private key path, and the third parameter is the X.509 certificate path
LuaApkSigner.generate_cert_rsa(certPath, pemPath, x509PemPath, rsaPath)

-- Sign the apkPath and output to signedApkPath, the second parameter is the private key path, the third parameter is the X.509 certificate path, if the fourth parameter (signedApkPath) is not passed or is false/nil, the signed Apk will overwrite apkPath
LuaApkSigner.sign_apk(apkPath, pemPath, x509PemPath, signedApkPath)