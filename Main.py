from AES128 import AES128 as AES

# Instantiate and run the encryption sequence
obj_enc = AES("Two One Nine Two", "Thats my Kung Fu")
obj_enc.run_encryption()
print(obj_enc.get_result())

# Instantiate and run the decryption sequence
obj_dec = AES(obj_enc.get_result(), "Thats my Kung Fu")
obj_dec.run_decryption()
print(obj_dec.get_result())