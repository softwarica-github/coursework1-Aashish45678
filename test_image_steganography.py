

import unittest
from image_stegnography import str2bin, bin2str, xor_encrypt_decrypt, encode, decode

class TestImageSteganography(unittest.TestCase):
    def test_str2bin_bin2str(self):
        print("Running Third Test.\n")
        # Test str2bin and bin2str functions
        data = "Hello, World!"
        binary_data = str2bin(data)
        self.assertEqual(bin2str(binary_data), data)

    def test_xor_encrypt_decrypt(self):
        print("Running Fourth Test.\n")
        # Test xor_encrypt_decrypt function
        data = "Secret Message"
        password = "password123"
        encrypted_data = xor_encrypt_decrypt(data, password)
        decrypted_data = xor_encrypt_decrypt(encrypted_data, password)
        self.assertEqual(data, decrypted_data)

    def test_encode_decode_with_password(self):
        print("Running First Test.\n")
        # Test encoding and decoding with password
        data = input("Enter the secret data with password: ")
        password = input("Enter the password for encoding and decoding: ")
        input_image = input("Enter the input image file path: ")
        output_image = input("Enter the output image file path: ")

        # Encoding
        encode(input_image, data, output_image, password)

        # Decoding
        output_image=output_image+".png"
        decoded_data = decode(output_image, password)

        # Check if the decoded data matches the original secret data
        self.assertEqual(data, decoded_data)

    def test_encode_decode_without_password(self):
        print("Running Second Test.\n")
        # Test encoding and decoding without password
        data = input("Enter the secret data without password: ")
        input_image = input("Enter the input image file path: ")
        output_image = input("Enter the output image file path: ")

        # Encoding
        encode(input_image, data, output_image)

        # Decoding
        output_image=output_image+".png"
        decoded_data = decode(output_image)

        # Check if the decoded data matches the original secret data
        self.assertEqual(data, decoded_data)

if __name__ == "__main__":
    unittest.main()

