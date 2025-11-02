# Application-Layer Security Utilities

This repository collects small, framework-agnostic Java utilities that demonstrate two classic security topics frequently discussed in MSCS-535:

- **OSI Layer 7 hardening** via composable request filters for rate limiting, CSRF validation, input allow-listing, and secure response headers.
- **One-time pad cryptography** implemented with modern Java primitives for key generation, XOR encryption, and decryption.

The code is intentionally dependency-free so it can be compiled with the standard JDK and dropped into servlet containers, Spring applications, or small teaching examples.

## Project Layout

```
src/main/java/com/example/security/
├── Layer7Security.java   # Application-layer protections and helper HTTP types
└── OneTimePad.java       # Standalone one-time pad helper and runnable demo
```

## Prerequisites

- Java 17+ (the examples rely on records and `HexFormat`, which were introduced in modern JDKs)

## Building

Compile both classes with `javac` (run from the repository root):

```bash
javac src/main/java/com/example/security/*.java
```

The command produces `.class` files alongside the sources. Add `-d out` if you prefer collecting build artifacts in a separate directory.

## Running the One-Time Pad Demo

After compiling, execute the `main` method in `OneTimePad` to generate a fresh key and ciphertext for the phrase "MY NAME IS UNKNOWN":

```bash
java -cp src/main/java com.example.security.OneTimePad
```

Each run prints the plaintext along with the randomly generated key and ciphertext in both hexadecimal and Base64 encodings. Because a new key is created every time, repeated executions yield different outputs.

## Using the Layer7Security Utilities

`Layer7Security` bundles several defensive building blocks that can wrap existing HTTP handlers:

- `RateLimiter` throttles requests from a client IP using a token-bucket algorithm.
- `InputValidator` enforces conservative allow-lists for URL paths and parameter values.
- `CsrfTokenManager` issues and validates Base64-encoded CSRF tokens tied to session identifiers.
- `SecurityHeaders` applies hardened response headers (CSP, X-Frame-Options, Referrer Policy, etc.).

The convenience method `secureHandle(HttpRequest request)` demonstrates how to combine these defenses before invoking business logic. Adapt the `HttpRequest` and `HttpResponse` helpers to match your web framework, or inject custom implementations into the constructor for advanced scenarios.

## Next Steps

- Swap the placeholder business logic in `secureHandle` with your real handler once the request passes validation.
- Persist CSRF tokens in a distributed session store if you deploy behind multiple servers.
- Extend the input validator with context-aware rules for application-specific parameters.

These examples are intentionally lightweight but provide a solid foundation for discussing real-world secure web application design.
