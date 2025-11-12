# Simple Ransomware Simulator

## Overview
Build an educational tool that safely demonstrates file encryption without causing actual damage, allowing security professionals to understand ransomware mechanics, test backup/recovery procedures, and train staff on ransomware awareness. This project teaches encryption implementation, secure file handling, and demonstrates ransomware attack workflows for defensive purposes.

## Step-by-Step Instructions

1. **Establish ethical boundaries and safety mechanisms** by creating a tool that works only on specifically designated test directories and cannot propagate to system files or other critical locations. Build in extensive warnings, confirmations, and ability to run in dry-run mode showing what would be encrypted without actually modifying files. Implement audit logging capturing every action for accountability and post-simulation analysis.

2. **Implement encryption using Python's cryptography library** (specifically `cryptography.fernet` or `cryptography.hazmat.primitives.ciphers`) to encrypt test files with strong symmetric encryption. Generate and store encryption keys in a controlled location, implement proper key management, and ensure encryption is genuinely strong (not simulated/weak encryption). Test encryption/decryption on sample files to verify the mechanism works correctly.

3. **Create isolated test environment setup** that prepares a designated directory structure for simulation: creates subdirectories with various file types (documents, images, databases), populates with realistic test data that looks like sensitive information, and establishes baseline file hashes for verification. Include instructions for users to test their backup/recovery procedures using this controlled test environment.

4. **Build file encryption logic** that recursively traverses the test directory structure, encrypts each file using the generated key, and optionally renames files to include encryption extension (e.g., .encrypted) mimicking real ransomware. Implement proper error handling so that if encryption fails on any file, the simulator can be stopped and rolled back, preventing accidental damage from bugs.

5. **Implement decryption capability** allowing authorized users to recover encrypted test files when the exercise is complete. Create a decryption utility requiring the encryption key, providing straightforward recovery process. Use this as educational moment: explain that real ransomware victims either pay ransoms (often ineffective) or lose data, while this controlled simulation provides recovery automatically.

6. **Add educational content and ransom note simulation** creating a text file that displays during/after encryption explaining how ransomware works, what just happened in the simulation, what recovery procedures should be followed, and key takeaways about prevention (backups, updates, email security). Make educational content the focus rather than ransom demands—this emphasizes defensive goals.

7. **Create comprehensive reporting and analysis tools** generating reports on what was encrypted, which files were affected, encryption statistics, time elapsed, and recovery verification. Build dashboards showing encryption progress, recovery status, and lessons learned from the simulation exercise, suitable for post-exercise debriefs with security teams.

8. **Build extensive documentation** emphasizing that this tool is for educational and authorized testing only—never use on systems without explicit permission from system owners. Include detailed setup instructions, disaster recovery procedures, staff training guidelines showing how to use the simulator for ransomware awareness training, and legal warnings about unauthorized testing. Compare to real ransomware techniques, discuss actual ransomware examples and their impact, and explain how understanding ransomware mechanics improves defense strategies.

## Key Concepts to Learn
- Symmetric encryption and key management
- File system operations and directory traversal
- Safe simulation practices and rollback capability
- Educational security demonstrations
- Backup and disaster recovery testing
- Incident response and recovery procedures

## Deliverables
- Controlled test environment setup
- File encryption with strong symmetric algorithms
- File decryption and recovery capability
- Encryption progress tracking and reporting
- Educational content and ransom notes
- Comprehensive audit logging and analysis
