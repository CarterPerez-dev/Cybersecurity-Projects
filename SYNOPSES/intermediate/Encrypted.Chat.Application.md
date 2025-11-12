# Encrypted Chat Application

## Overview
Build a peer-to-peer encrypted chat application using WebSockets with end-to-end encryption via asymmetric and symmetric cryptography, implementing Diffie-Hellman key exchange for secure key establishment. This project teaches cryptographic protocols, network communication, and demonstrates practical implementation of secure communication systems.

## Step-by-Step Instructions

1. **Understand cryptographic fundamentals and key exchange** by learning public-key cryptography (asymmetric encryption using public/private key pairs), symmetric encryption (faster but requires shared secret), and Diffie-Hellman key exchange (securely establishing shared secret over public channels). Study protocols that combine them: asymmetric crypto for initial key establishment and authentication, symmetric crypto for bulk message encryption (more efficient). Choose encryption libraries like `cryptography` for Fernet (pre-configured symmetric encryption) or build custom RSA+AES implementation.

2. **Implement WebSocket server** using `websockets` or `socketio` library to handle real-time bidirectional communication between chat clients. Build connection management handling multiple simultaneous clients, message routing between sender and recipient(s), and graceful disconnection. Implement message queuing ensuring no messages are lost if recipient temporarily disconnects, and provide delivery confirmation when messages reach recipients.

3. **Build Diffie-Hellman key exchange** establishing secure shared secrets between communicating peers over public channels. Implement DH parameter generation, public key computation and exchange with other participants, shared secret derivation, and session key generation. Use the established shared secret to initialize symmetric encryption for all subsequent messages, ensuring eavesdroppers cannot decrypt communication even if they see all exchanged data.

4. **Implement end-to-end encryption** using symmetric encryption (Fernet or AES-GCM) to encrypt all chat messages with the key established through Diffie-Hellman exchange. Encrypt messages on sender's device before transmission, decrypt on recipient's device—ensure server never has access to plaintext or keys. Implement message authentication codes ensuring message integrity (detect tampering) and providing authenticity (confirm sender identity).

5. **Create user authentication and identity management** establishing trust between communicating parties, preventing impersonation or man-in-the-middle attacks. Implement public key fingerprint verification (users manually verify fingerprints through out-of-band channels), certificate-based authentication, or trusted contact lists. Build UI allowing users to see key fingerprints and confirm they're communicating with intended parties.

6. **Build React frontend** creating intuitive chat interface displaying conversations, encrypted message indicators, user presence status, and key fingerprint verification. Implement real-time message display as they arrive, typing indicators, message timestamps, and conversation history viewing. Add UI elements confirming message encryption status and preventing users from communicating with unverified identities.

7. **Implement message history and persistence** storing encrypted message history locally on user devices with encryption keys never stored unencrypted. Provide options for viewing past conversations and searching messages. Implement conversation export functionality allowing users to archive conversations, and secure deletion ensuring old messages cannot be recovered from disk after deletion.

8. **Build comprehensive documentation** explaining cryptography concepts used in implementation, discussing security properties and threat models (provides confidentiality and integrity, but not anonymity if usernames known), and providing deployment instructions. Compare your implementation to established secure chat applications (Signal, Wire, Element), discuss limitations and trade-offs in your implementation, explain how this fits into broader secure communications infrastructure, and include security considerations for production deployment.

## Key Concepts to Learn
- Asymmetric and symmetric encryption
- Diffie-Hellman key exchange protocol
- WebSocket communication
- Message authentication and integrity
- User identity verification and trust
- React frontend development
- Secure local data storage

## Deliverables
- WebSocket-based chat server
- Diffie-Hellman key exchange implementation
- End-to-end encryption with symmetric crypto
- User authentication and identity verification
- React frontend with encryption indicators
- Secure message history storage
- Multi-user peer-to-peer communication
