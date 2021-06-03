package test.db;

import db.Database;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.PublicKey;

class DatabaseTest {

    Database db;

    @org.junit.jupiter.api.BeforeEach
    void setUp() {
        db = new Database();
    }

    @org.junit.jupiter.api.AfterEach
    void tearDown() {
    }

    @Test
    void generateKeyPair() {
        Object[] keyPair = db.generateKeyPair();
        Assertions.assertTrue(keyPair[0] instanceof PublicKey);
        Assertions.assertTrue(keyPair[1] instanceof PrivateKey);
    }

    @Test
    void issueCertificate() {
    }
}