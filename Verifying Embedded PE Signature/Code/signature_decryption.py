from Crypto.PublicKey import RSA
import binascii

def decrypt_signature(public_key_hex, signature_hex):
    # Convert the hex strings back to bytes
    public_key_bytes = binascii.unhexlify(public_key_hex)
    signature_bytes = binascii.unhexlify(signature_hex)
    
    # Import the public key
    rsa_key = RSA.importKey(public_key_bytes)
    
    # Manually decrypt the signature by simulating the public key decrypt operation
    modulus = rsa_key.n
    modulus_len = rsa_key.size_in_bytes()

    # Convert the signature into an integer
    signature_int = int.from_bytes(signature_bytes, byteorder='big')

    # Perform the RSA "decryption" (modular exponentiation)
    recovered_plaintext_int = pow(signature_int, rsa_key.e, modulus)

    # Convert the decrypted integer back to bytes
    recovered_plaintext_bytes = recovered_plaintext_int.to_bytes(modulus_len, byteorder='big')

    # Output the padded plaintext. You would need to strip the padding.
    print("\nRecovered the plaintext (with padding)")
    print(' '.join(f'{byte:02X}' for byte in recovered_plaintext_bytes))

    # PKCS#1 v1.5 padding starts with 0x00 0x01 followed by padding bytes (0xFF), and then the plaintext.
    # Remove the padding manually (look for the 0x00 separator)
    padding_separator_index = recovered_plaintext_bytes.index(b'\x00', 2)  # First two bytes are 0x00 0x01
    plaintext = recovered_plaintext_bytes[padding_separator_index+1:]

    # Print the plaintext
    print("\nRecovered the plaintext")
    print(' '.join(f'{byte:02X}' for byte in plaintext))    

    
# Decrypt the signature
signature_hex = 'CAA13F31ACD990AAA7B50EDA790F46FBFB2293F3CB8DD60B6C331093299EF8E910BE2BAD0E1E7D4288492B147913EC1313852517C54FB696F8DCE39A772EE3D7CF8C9BFCEE31613A7425302F5BE1D198BCF9CA3FF9D05BAA79248A953D7FE793A87BD9FE70BCAA9A63B23B8F591F49B4F52AED9AB19F9498FEE220BD35A3EFE9A9B3CA3DFF4189E3F0AC92AF52F74722F801AB9634B9AA735FFA60C13BE9C40C915FFC341F147927B2DC00DD99DBB94EA82370CF1DC94907600EFAA0E93E3245818765C79B112D9D8FA91AC055132782331FF2267A00226175340813801C0D748089D59BFB72139752789871353501B49A655FDCCDE80F5003660D2AF1A56502'
public_key_hex = '3082010A0282010100CEB7C90B73B3F74FB30A221A2E6077B03059A7ABC032BBB14E85909069B570069D954B85B207641EE134014FC681CE700D0C43E31CA35D3D3F17CF970D6A58BA5C779F4BC8BF597B45D2F4AC3FC344BFA9811EE036A757F0DB007F174747B09DC67D9E5CD2C3C98E496C898A8FC39F71279E2433DD483A088ED8E5338CD0258CF89B8C259F1FB5334354CF1DCE1DC1E8A5B3C18422B6C145BEC85B088E6CBD768D64F8621EF535082F27D167EBE5210FDC76BA4DDD2E3F38BF0B7536E1508AD289C485747D5B11351DDA6D054E2EAA43BA06EBD12CCD2FAA3CC733872F93978861B083A7A4897035FF65D763BC9515CDFDB6579D0ED6634A335B7B1D73CF04970203010001'

decrypt_signature(public_key_hex, signature_hex)
