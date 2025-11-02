package com.example.security;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Utility methods for demonstrating an information-theoretically secure
 * one-time pad. This example performs the XOR operation byte-for-byte using
 * a cryptographically strong random key that is the same length as the
 * plaintext.
 */
public final class OneTimePad {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private OneTimePad() {
    }

    /**
     * Generates a random key of the requested length using a CSPRNG.
     */
    public static byte[] generateKey(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("length must be positive");
        }
        byte[] key = new byte[length];
        SECURE_RANDOM.nextBytes(key);
        return key;
    }

    /**
     * Encrypts the given plaintext using the supplied key with an XOR
     * operation. The key must be the same length as the plaintext for the
     * result to be a true one-time pad.
     */
    public static byte[] encrypt(byte[] plaintext, byte[] key) {
        Objects.requireNonNull(plaintext, "plaintext");
        Objects.requireNonNull(key, "key");
        if (plaintext.length != key.length) {
            throw new IllegalArgumentException("Plaintext and key must have the same length");
        }
        byte[] ciphertext = new byte[plaintext.length];
        for (int i = 0; i < plaintext.length; i++) {
            ciphertext[i] = (byte) (plaintext[i] ^ key[i]);
        }
        return ciphertext;
    }

    /**
     * Decrypts a one-time pad ciphertext using the original key.
     */
    public static byte[] decrypt(byte[] ciphertext, byte[] key) {
        return encrypt(ciphertext, key);
    }

    /**
     * Demonstrates encrypting the message "MY NAME IS UNKNOWN" with a
     * one-time pad and prints the randomly generated key and ciphertext in
     * both hexadecimal and Base64 for readability.
     */
    public static void main(String[] args) {
        String plaintext = "MY NAME IS UNKNOWN";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        byte[] key = generateKey(plaintextBytes.length);
        byte[] ciphertext = encrypt(plaintextBytes, key);

        HexFormat hex = HexFormat.of();
        String keyHex = hex.formatHex(key);
        String cipherHex = hex.formatHex(ciphertext);

        String keyBase64 = Base64.getEncoder().encodeToString(key);
        String cipherBase64 = Base64.getEncoder().encodeToString(ciphertext);

        System.out.println("Plaintext: " + plaintext);
        System.out.println("Key (hex): " + keyHex);
        System.out.println("Ciphertext (hex): " + cipherHex);
        System.out.println("Key (Base64): " + keyBase64);
        System.out.println("Ciphertext (Base64): " + cipherBase64);
    }
}
