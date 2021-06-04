package test.protocol_runs;

import Auto.Auto;
import Interfaces.CommunicatorExtended;
import db.Database;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import receptionTerminal.ReceptionTerminal;

import java.io.File;
import java.nio.file.Paths;
import java.util.Objects;

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
        //Delete all log files
        String path = Paths.get("").toAbsolutePath().toString();
        for (File file : Objects.requireNonNull(new File(path).listFiles())) {
            if (!file.isDirectory() && file.getName().endsWith(".log")) {
                System.out.println("Deleting: " + file.getAbsolutePath());
                file.delete();
            }
        }
    }

    @Test
    void fullRun() throws CommunicatorExtended.AuthenticationFailedException, CommunicatorExtended.ProcessFailedException {
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
        rt.blockCard(new byte[]{81, 55, 62, -117, 111});
    }

    @Test
    void successiveFullRuns() throws CommunicatorExtended.AuthenticationFailedException, CommunicatorExtended.ProcessFailedException {
        for (int i = 0; i < 32; i++) {
            System.out.println(" ========= Run " + i + " ========= ");
            fullRun();
        }
    }

    /* We need this test because we use threads, which are inherently unpredictable in their behaviour */
    @Test
    void fourTwentySuccessiveFullRuns() throws CommunicatorExtended.AuthenticationFailedException, CommunicatorExtended.ProcessFailedException {
        for (int i = 0; i < 420; i++) {
            System.out.println(" ========= Run " + i + " ========= ");
            fullRun();
        }
    }
}
