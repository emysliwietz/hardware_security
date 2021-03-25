package db;

import org.junit.jupiter.api.Assertions;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class DatabaseTest {

    @org.junit.jupiter.api.BeforeEach
    void setUp() {
    }

    @org.junit.jupiter.api.AfterEach
    void tearDown() {
    }

    @org.junit.jupiter.api.Test
    void createHash() {
        byte[] hello_world_hash = Database.createHash("Hello World".getBytes(StandardCharsets.UTF_8));
        byte[] actual_sha_512_hello_world_hash = ("2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246" +
                "fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27" +
                "acb15bfb1447f459b").getBytes(StandardCharsets.UTF_8);
        Assertions.assertArrayEquals(actual_sha_512_hello_world_hash, hello_world_hash);
    }
}