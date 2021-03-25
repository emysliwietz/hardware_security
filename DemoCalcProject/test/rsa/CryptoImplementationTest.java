package rsa;

import db.Database;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class CryptoImplementationTest {

    CryptoImplementation ci;

    @BeforeEach
    void setUp() {
        ci = new Database();
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void generateNonce() {
        HashSet<UUID> hs = new HashSet<>();
        for(int i = 0; i < 1000; i++){
            UUID n = ci.generateNonce();
            Assertions.assertFalse(hs.contains(n));
            hs.add(n);
        }
    }

    @Test
    void getCertificate() {
    }

    @Test
    void createHash() {
        byte[] hash = ci.createHash("Hello World".getBytes());
        String actualHash = "2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853" +
                "d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b";
        Assertions.assertEquals(actualHash, new String(hash));
    }

    @Test
    void hashAndSign() {
    }

    @Test
    void sign() {
    }

    @Test
    void unsign() {
    }

    @Test
    void testGenerateNonce() {
    }

    @Test
    void testGetCertificate() {
    }

    @Test
    void testCreateHash() {
    }

    @Test
    void testHashAndSign() {
    }

    @Test
    void testSign() {
    }

    @Test
    void testUnsign() {
    }
}