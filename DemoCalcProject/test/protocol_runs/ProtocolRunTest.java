package test.protocol_runs;

import Auto.Auto;
import Interfaces.CommunicatorExtended;
import db.Database;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import receptionTerminal.ReceptionTerminal;

import static org.junit.jupiter.api.Assertions.*;

public class ProtocolRunTest {
    ReceptionTerminal rt;
    Database db;
    Auto a;

    @BeforeEach
    void setUp() {
        db = new Database();
        rt = db.generateTerminal();
        a = db.generateAuto();
        Thread t1 = new Thread(() -> db.generateCard(rt));
        Thread t2 = new Thread(() -> rt.initialDataForSC());
        t1.start();
        t2.start();
        try {
            t1.join();
            t2.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void fullRun() {
        rt.cardAuthenticationInitiate();
        rt.carAssignmentInitiate();
        assertDoesNotThrow(() -> a.authenticateSCInitiate());
        for (int i = 0; i < 10; i++) {
            a.kilometerageUpdate();
        }
        rt.cardAuthenticationInitiate();
        rt.carReturnInitiate();
    }

    @Test
    void autoWithoutTerminalFirst() {
        Throwable cardNotInitializedException = assertThrows(CommunicatorExtended.CardNotInitializedException.class,
                () -> a.authenticateSCInitiate());
        assertEquals("Please initialize the card in the Reception Terminal first", cardNotInitializedException.getMessage());
    }

    @Test
    void blockCard() {
        rt.blockCard();
    }

    @Test
    void successiveFullRuns() {
        for(int i = 0; i < 32; i++) {
            fullRun();
        }
    }
}
