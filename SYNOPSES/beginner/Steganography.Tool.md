# Steganography Tool

## Overview
Create a tool that hides secret messages inside image files using least significant bit (LSB) steganography, allowing covert communication through seemingly innocent images. This project teaches data encoding techniques, image file formats, and demonstrates how information can be secretly embedded and extracted from digital media.

## Step-by-Step Instructions

1. **Understand LSB steganography principles** by learning that each pixel in an image is represented by color values (typically 0-255 for each RGB channel), and the least significant bit is the rightmost bit in the binary representation—changing it minimally affects the visible image but can encode data. For example, if a red channel value is 255 (binary: 11111111), changing the LSB to create 254 (binary: 11111110) is imperceptible to human eyes.

2. **Research image file formats** (PNG and BMP are ideal for LSB steganography because they're lossless—JPEG compression would destroy your hidden message). Understand how pixel data is stored in these formats: BMP stores pixel data directly, PNG uses compression but preserves data, and JPEG uses lossy compression making it unsuitable. Implement library support for reading and writing these formats using `Pillow`.

3. **Implement message encoding functionality** that converts your secret message to binary, then hides those bits in the LSB of image pixels. Process pixels sequentially (typically left-to-right, top-to-bottom), replace the LSB of each color channel with message bits, and reconstruct the modified image with the hidden data embedded. Include a capacity calculator showing how much data can fit in a given image.

4. **Build message extraction capability** that reverses the encoding process—read the LSB from each pixel in sequence and reconstruct the original binary message. Implement length encoding (store the message length in the first few pixels) so the decoder knows when to stop reading and can properly handle variable-length messages.

5. **Add password protection** by encrypting the secret message before encoding it into the image—use symmetric encryption like AES to encrypt the plaintext message, then encode the encrypted bytes using LSB steganography. This provides two layers of security: even if someone extracts the hidden data, they can't read it without the password.

6. **Support both PNG and BMP formats** by implementing format-specific handling in your library interactions. Add automatic format detection for input images and let users specify output format—include guidance on which formats are appropriate for steganography and warnings about using lossy compression formats.

7. **Create a clean command-line interface** with options for encoding (input image, message text, output filename, optional password) and decoding (steganographic image, optional password). Implement verbose mode showing encoding/decoding progress, capacity information, and data verification to ensure the hidden message was correctly embedded and extracted.

8. **Build comprehensive documentation** explaining the steganography concept, discussing LSB technique limitations and detection methods (steganalysis), providing examples of encoding/decoding images, and explaining practical use cases (covert communication in restricted environments). Include warnings about legal implications of hidden communications, discuss how steganography differs from encryption, and note that LSB steganography is trivial to detect with proper tools but effective for basic covert communication.

## Key Concepts to Learn
- Least significant bit (LSB) concept and manipulation
- Image file formats and pixel data representation
- Data encoding and binary operations
- File I/O and image manipulation libraries
- Encryption integration for enhanced security
- Steganography detection and limitations

## Deliverables
- LSB steganography encoder/decoder
- Support for PNG and BMP image formats
- Password protection with encryption
- Capacity calculation and verification
- Command-line interface with encoding/decoding modes
