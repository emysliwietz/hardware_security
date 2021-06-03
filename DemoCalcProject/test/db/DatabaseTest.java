package test.db;

import db.Database;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DatabaseTest {

    Database db;

    @BeforeEach
    void setUp() {
        db = new Database();
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void generateKeyPair() {
        Object[] keyPair = db.generateKeyPair();
        Assertions.assertTrue(keyPair[0] instanceof RSAPublicKey);
        Assertions.assertTrue(keyPair[1] instanceof RSAPrivateKey);
    }
}