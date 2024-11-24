# LuaApkSigner

使用C语言实现的基于OpenSSL和libzip库实现的APK V1签名工具,带有Lua绑定

---

## Example Usage:

```lua
local LuaApkSigner = require("LuaApkSigner")

-- 为apkPath生成MANIFEST.MF文件并写入到manifestPath
LuaApkSigner.generate_manifest(apkPath, manifestPath)

-- 为manifestPath生成CERT.SF文件并写入到certPath中
LuaApkSigner.generate_cert_sf(manifestPath, certPath)

-- 将pk8Path转换为pem格式并写入到pemPath中
LuaApkSigner.convert_pk8_to_pem(pk8Path, pemPath)

-- 为certPath生成CERT.RSA文件并写入到rsaPath中,第二个参数为私钥的路径,第三个参数为X.509证书的路径
LuaApkSigner.generate_cert_rsa(certPath, pemPath, x509PemPath, rsaPath)

-- 将apkPath进行签名并输出到signedApkPath中,第二个参数为私钥的路径,第三个参数为X.509证书的路径,如果第四个参数(signedApkPath)未传入或传入false/nil,则会将签名后的Apk覆盖至apkPath中
LuaApkSigner.sign_apk(apkPath, pemPath, x509PemPath, signedApkPath)