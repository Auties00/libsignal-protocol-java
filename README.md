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

## Benchmarks

Performance comparison against the [original Java implementation](https://github.com/signalapp/libsignal-protocol-java/) and [Rust bindings](https://github.com/signalapp/libsignal/).
Benchmarks run using JMH with 10 iterations, measuring average time per operation.
The benchmark was run on an i7 9700K.
You can find the benchmark, alongside a log message of the run, in the [test directory](./src/test/java/com/github/auties00/libsignal/benchmark).

> **IMPORTANT:**
> The Rust Bindings version being tested is `0.72.0`, not the latest, which as of this data is `0.86.5`,
> as after the latest version being tested, Signal introduced post quantum cryptographic measures, 
> which this library doesn't support yet.

### Session Operations (1:1 Messaging)

| Benchmark                | This Library  | Old Java  | Rust Bindings |
|--------------------------|---------------|-----------|---------------|
| Encrypt Small            | **0.84 ms**   | 1.29 ms   | 5.39 ms       |
| Encrypt Medium           | **1.15 ms**   | 1.66 ms   | 7.83 ms       |
| Encrypt Large            | **20.35 ms**  | 25.56 ms  | 85.05 ms      |
| Encrypt ExtraLarge       | **334.03 ms** | 462.53 ms | 1375.36 ms    |
| Decrypt Small            | **1.65 ms**   | 2.12 ms   | 12.43 ms      |
| Decrypt Medium           | **1.90 ms**   | 2.37 ms   | 6.37 ms       |
| Decrypt Large            | **17.49 ms**  | 20.51 ms  | 46.86 ms      |
| Decrypt ExtraLarge       | **335.67 ms** | 392.49 ms | 567.27 ms     |
| Out-of-Order Decrypt     | **1.71 ms**   | 3.10 ms   | 9.87 ms       |
| Message Key Limit Stress | **13.60 ms**  | 48.06 ms  | 287.83 ms     |

### Group Operations

| Benchmark                | This Library  | Old Java  | Rust Bindings |
|--------------------------|---------------|-----------|---------------|
| Encrypt Small            | **10.10 ms**  | 11.17 ms  | 7.71 ms       |
| Encrypt Medium           | **10.47 ms**  | 11.67 ms  | 6.83 ms       |
| Encrypt Large            | **34.47 ms**  | 38.94 ms  | 42.01 ms      |
| Encrypt ExtraLarge       | **450.15 ms** | 532.66 ms | 572.30 ms     |
| Decrypt Small            | **14.95 ms**  | 15.64 ms  | 7.64 ms       |
| Decrypt Medium           | **15.14 ms**  | 16.11 ms  | 8.44 ms       |
| Decrypt Large            | **27.73 ms**  | 30.14 ms  | 22.18 ms      |
| Decrypt ExtraLarge       | **313.49 ms** | 427.10 ms | 332.68 ms     |
| Out-of-Order Decrypt     | **15.03 ms**  | 16.50 ms  | 8.60 ms       |
| Message Key Limit Stress | **33.18 ms**  | 59.29 ms  | 91.52 ms      |