import gostcrypto

password = b'password'
salt = b'salt'

pbkdf_obj = gostcrypto.gostpbkdf.new(password, salt, 4096)
pbkdf_result = pbkdf_obj.derive(32)
print(pbkdf_result.hex())
