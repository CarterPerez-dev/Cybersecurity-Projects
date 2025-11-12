# Hash Cracker

## Overview
Build a hash cracking tool that attempts to match unknown hashes against wordlists and brute-force attempts to recover original passwords. This project teaches hash algorithm mechanics, attack methodologies, and demonstrates why proper password hashing (with salts and slow algorithms) is critical for security.

## Step-by-Step Instructions

1. **Understand hash algorithms and limitations** by studying MD5, SHA1, and SHA256 hash functions—learn that these are one-way mathematical functions producing fixed-length outputs that are deterministic (same input always produces same output). Recognize that MD5 and SHA1 are cryptographically broken and should not be used for password storage, but understanding how to crack them teaches important security principles about why newer algorithms like bcrypt exist.

2. **Implement hash generation capability** so you can produce hashes to test your cracker—build functions that hash input strings with MD5, SHA1, and SHA256 algorithms. Verify your implementation by testing against known hash values and comparing outputs with standard tools like `openssl` or online hash calculators.

3. **Create wordlist-based dictionary attack** by reading a wordlist file (common password lists available online) and hashing each word, comparing it against the target hash. This teaches the attack methodology used when hackers have stolen password hashes and attempt to recover the plaintext by trying common passwords—it's fast because it only tries likely passwords.

4. **Implement brute-force attack capability** that generates all possible character combinations up to a specified length and tests each one. Start with lowercase letters only, then expand to uppercase, numbers, and special characters—implement this efficiently using string generators or itertools to avoid storing massive lists in memory.

5. **Add salted hash support** by understanding how salts (random data added to passwords before hashing) prevent dictionary attacks and rainbow tables. Implement cracking of salted hashes by accepting the salt as input and prepending/appending it to each guess before hashing—explain why salts are essential and why brute-forcing salted hashes takes exponentially longer.

6. **Optimize performance** by implementing multi-threading or multi-processing to crack hashes faster using multiple CPU cores. Add progress reporting showing hashes-per-second, estimated time remaining, and current progress through the wordlist or brute-force space—performance optimization teaches practical programming skills beyond basic hash cracking.

7. **Build configuration options** allowing users to specify target hash type, hash value, wordlist file path, brute-force character sets, maximum password length, and number of threads. Support loading multiple hashes at once and determining when any of them are cracked, enabling batch cracking operations.

8. **Create comprehensive documentation** explaining hash algorithms and their security properties, discussing why unsalted hashes are dangerous, explaining the differences between dictionary and brute-force attacks, and providing real-world examples of password cracking in penetration testing contexts. Include warnings about the computational effort required for strong passwords and explain why proper password hashing practices (bcrypt, argon2, scrypt) make cracking prohibitively expensive.

## Key Concepts to Learn
- Cryptographic hash functions and properties
- Dictionary attack methodology
- Brute-force attack optimization
- Password salting and iterations
- Multi-threading and performance optimization
- Rainbow tables and their limitations

## Deliverables
- Hash cracker supporting MD5, SHA1, SHA256
- Dictionary attack with wordlist support
- Brute-force mode with character set options
- Multi-threaded performance optimization
- Salted hash support and configuration options
