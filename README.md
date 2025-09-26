# libsignal-protocol-java

A rewrite of the original [libsignal-protocol-java](https://github.com/signalapp/libsignal-protocol-java/) library, providing a modern Java implementation of the Signal Protocol for end-to-end encryption.

## Overview

This library implements the Signal Protocol, which provides end-to-end encryption for messaging applications. 
The Signal Protocol combines the Double Ratchet algorithm, prekeys, and a triple Diffie-Hellman handshake to provide forward secrecy and break-in recovery.

## Features

- **Double Ratchet Algorithm**: Provides forward secrecy and break-in recovery
- **Pre-key bundles**: Enable asynchronous key exchange
- **Session management**: Handle multiple concurrent sessions
- **Group messaging**: Support for encrypted group communications
- **Device management**: Handle multiple devices per user
- **Fingerprint verification**: Verify message authenticity
- **Modern Java**: Built with Java modules support and modern best practices