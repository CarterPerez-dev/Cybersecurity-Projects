# Caesar Cipher Encoder/Decoder

## Overview
Build a command-line tool that implements the Caesar cipher, one of history's simplest encryption methods where each character is shifted by a fixed number of positions in the alphabet. This project teaches fundamental cryptography concepts, string manipulation, and serves as an excellent foundation for understanding more complex encryption systems.

## Step-by-Step Instructions

1. **Understand the Caesar cipher algorithm** by learning how it shifts each letter in a message by a consistent number (the "key") through the alphabet—for example, with a shift of 3, 'A' becomes 'D', 'B' becomes 'E', and so on. Recognize that there are only 26 possible meaningful shifts since shifting by 26 returns to the original, making this cipher trivially weak but conceptually instructive.

2. **Build the encryption function** that takes a plaintext message and a shift key, then iterates through each character and applies the shift formula. For each letter, calculate its position in the alphabet (0-25), add the shift value, use modulo 26 to wrap around the alphabet, and convert back to a character—handle both uppercase and lowercase letters appropriately.

3. **Implement the decryption function** by simply reversing the process: subtract the shift value instead of adding it, or equivalently encrypt with the negative shift (shift of -3 to decrypt something shifted by 3). Recognize that decryption and encryption are mathematically symmetric operations in the Caesar cipher.

4. **Add special character handling** by preserving spaces, punctuation, and numbers exactly as they appear in the original message—only shift alphabetic characters. This maintains readability and prevents corrupting important formatting or numerical data in the message.

5. **Create brute-force decryption capability** that tries all 26 possible shifts automatically when you don't know the encryption key. Output all 26 possible decryptions with their shift values, allowing the user to identify which one produces intelligible plaintext—this demonstrates why Caesar cipher is so weak and easily broken.

6. **Build a user-friendly CLI interface** with clear prompts asking whether the user wants to encrypt or decrypt, what message to process, and (for encryption) what shift key to use. Provide helpful error messages if invalid input is detected and allow users to process multiple messages in one session without restarting the program.

7. **Add analysis features** like character frequency counting that displays how often each letter appears in the plaintext and ciphertext, demonstrating how frequency analysis is used to break simple substitution ciphers without knowing the key. Include statistics like vowel-to-consonant ratios and word pattern analysis.

8. **Create comprehensive documentation** explaining the history and limitations of Caesar cipher, why it's broken by modern standards, and how it relates to more sophisticated encryption methods. Include examples of encrypting and decrypting messages, explain the brute-force attack methodology, and discuss practical applications for educational learning about cryptography concepts.

## Key Concepts to Learn
- String manipulation and character encoding
- Mathematical modulo operations
- Brute-force attack methodology
- Algorithm design and implementation
- Basic cryptography principles

## Deliverables
- Functional encryption/decryption CLI tool
- Brute-force decryption with all 26 possible shifts
- Character frequency analysis
- Well-documented code with examples and explanations
