package gui;

import Auto.Auto;
import Interfaces.CommunicatorExtended;
import db.Database;
import javafx.fxml.FXML;
import javafx.scene.Cursor;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollBar;
import javafx.scene.control.TextArea;
import receptionTerminal.ReceptionTerminal;

/**
 * @author Matti Eisenlohr
 * @author Egidius Mysliwietz
 */
public class SmartcardGUIController {
    @FXML
    Label insLab;
    @FXML
    Label left0;
    @FXML
    Label left1;
    @FXML
    Label left2;
    @FXML
    Label right0;
    @FXML
    Label right1;
    @FXML
    Label right2;
    @FXML
    TextArea display;
    @FXML
    Label l0;
    @FXML
    Label l1;
    @FXML
    Label l2;
    @FXML
    Label l3;
    @FXML
    Label r0;
    @FXML
    Label r1;
    @FXML
    Label r2;
    @FXML
    Label r3;
    @FXML
    Label inscard;
    boolean driving = false;
    int kmm = 0;
    private states state = states.INIT;
    //private Smartcard sc;
    private Auto a;
    private ReceptionTerminal rt;
    private Database db;

    public void setVars(Auto a, ReceptionTerminal rt, Database db) {
        //this.sc = sc;
        this.a = a;
        this.rt = rt;
        this.db = db;
    }

    @FXML
    private void blockCard() {
        display.setWrapText(true);
        display.setText("Do you wish to report the theft of your card?");
        right2.setText("Confirm");
        left2.setText("Abort");
        l2.setCursor(Cursor.HAND);
        r2.setOnMouseClicked(event -> block());
        l2.setOnMouseClicked(event -> ok());
    }

    private void block() {
        //TODO: Create codes and APDU for this stuff
        Thread t1 = new Thread(() -> rt.blockCard(new byte[]{81, 55, 62, -117, 111}));
        Thread t2 = new Thread(() -> db.deleteCard(rt));
        t1.start();
        t2.start();
        try {
            t1.join();
            t2.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        display.setText("Card successfully blocked by employee");
        left2.setText("");
        l2.setOnMouseClicked(null);
        right2.setText("OK");
        r2.setOnMouseClicked(event -> ok());
    }

    @FXML
    private void insert() {
        right2.setText("");
        r2.setCursor(Cursor.DEFAULT);
        insLab.setOnMouseClicked(null);
        insLab.setCursor(Cursor.DEFAULT);
        inscard.setText("");
        inscard.setCursor(Cursor.DEFAULT);
        display.setWrapText(true);
        ScrollBar scrollBarv = (ScrollBar) display.lookup(".scroll-bar:vertical");
        scrollBarv.setDisable(true);
        display.setText("Please specify which device you want to insert your card into.");
        left0.setText("Car");
        right0.setText("Reception");
        l0.setCursor(Cursor.HAND);
        r0.setCursor(Cursor.HAND);
        l0.setOnMouseClicked(event -> carStart());
        r0.setOnMouseClicked(event -> {
            try {
                receptionAuth();
            } catch (CommunicatorExtended.ProcessFailedException e) {
                display.setText(e.getMessage());
                e.printStackTrace();
            } catch (CommunicatorExtended.AuthenticationFailedException e) {
                display.setText(e.getMessage());
                e.printStackTrace();
            }
        });
    }

    private void receptionAuth() throws CommunicatorExtended.ProcessFailedException, CommunicatorExtended.AuthenticationFailedException {
        l0.setCursor(Cursor.DEFAULT);
        r0.setCursor(Cursor.DEFAULT);
        left0.setText("");
        right0.setText("");
        System.out.println("Authentication protocol");
        display.setText("");
        l0.setOnMouseClicked(null);
        r0.setOnMouseClicked(null);
        int success = rt.cardAuthenticationInitiate();
        if (success == -1){
            display.setText("Card is blocked.");
            return;
        } else if (success < -1){
            display.setText("Something went wrong. Please try again.");
            return;
        }

        if (state == states.INIT) {
            System.out.println("Car assignment");
            int i = rt.carAssignmentInitiate();

            if (i == 0){
                display.setText("Your car is: Fiat Multipla with plate HN J 5099");
            } else if (i == -1){
                display.setText("Card is not authenticated. Please try again.");
            } else if (i == -2){
                display.setText("Something went wrong. Please try again.");
            } else if (i == -3){
                display.setText("Please request a car.");
            }else if (i == -4){
                display.setText("Timeout Database. Please try again.");
            } else {
                display.setText("Something went wrong. Please try again.");
            }

            state = states.ASSIGNED;
            right2.setText("OK");
            r2.setCursor(Cursor.HAND);
            r2.setOnMouseClicked(event -> ok());
        } else {
            System.out.println("Car return");
            int i = rt.carReturnInitiate();
            if (i == 0){
                display.setText("Total kilometers driven: " + rt.kilometerage + "km\nPrice: " + String.format("%.2f€", 0.30 * rt.kilometerage));
            } else if (i == -1){
                display.setText("Card is not authenticated. Please try again.");
            } else if (i == -2){
                display.setText("Something went wrong. Please try again.");
            } else if (i == -3){
                display.setText("Kilometerage on card is incorrect. Card has been manipulated.");
            } else {
                display.setText("Something went wrong. Please try again.");
            }

            state = states.INIT;
            right2.setText("OK");
            r2.setCursor(Cursor.HAND);
            r2.setOnMouseClicked(event -> ok());
        }
    }

    private void ok() {
        a.deselect();
        inscard.setText("Insert Card");
        inscard.setCursor(Cursor.HAND);
        right2.setText("Report theft");
        r2.setCursor(Cursor.HAND);
        r2.setOnMouseClicked(event -> blockCard());
        left2.setText("");
        l2.setCursor(Cursor.DEFAULT);
        l2.setOnMouseClicked(null);
        left0.setText("");
        l0.setCursor(Cursor.DEFAULT);
        l0.setOnMouseClicked(null);
        display.setText("Welcome! Please insert your card.");
        insLab.setCursor(Cursor.HAND);
        insLab.setOnMouseClicked(event -> insert());
    }

    private void carStart() {
        try {
            int i  = a.authenticateSCInitiate();
            if (i == -1){
                display.setText("Something went wrong. Please try again.");
            }
        } catch (CommunicatorExtended.CardNotInitializedException | CommunicatorExtended.AuthenticationFailedException e) {
            display.setText(e.getMessage());
            return;
        }
        display.setText("Current kilometerage: " + kmm + "km");
        driving = false;
        l0.setCursor(Cursor.HAND);
        r0.setCursor(Cursor.DEFAULT);
        left0.setText("Start Driving");
        right0.setText("");
        r0.setOnMouseClicked(null);
        if (state != states.ASSIGNED) {
            display.setText("You need to have a car assigned first!");
            right2.setText("OK");
            r2.setCursor(Cursor.HAND);
            r2.setOnMouseClicked(event -> ok());
            return;
        }
        System.out.println("Car start");
        l0.setOnMouseClicked(event -> drive());
        inscard.setText("Stop the car");
        insLab.setCursor(Cursor.HAND);
        insLab.setOnMouseClicked(event -> ok());
    }

    public void updateKmm() {
        try {
            kmm = a.kilometerageUpdate();
        } catch (CommunicatorExtended.ProcessFailedException e) {
            e.printStackTrace();
        }
        if (kmm == -1){
            display.setText("Something went wrong. Kilometerage failed to update.");
        } else if (kmm == -2){
            display.setText("Something went wrong. Please try again.");
        } else if (kmm == -3){
            display.setText("Kilometerage does not match. Possible manipulation detected.");
        } else {
            display.setText("Current kilometerage: " + kmm + "km");
        }
    }

    public void drive() {
        driving = true;
        left0.setText("Stop Driving");
        l0.setOnMouseClicked(event -> carStart());
        right0.setText("Drive 1km");
        r0.setOnMouseClicked(event -> updateKmm());
        r0.setCursor(Cursor.HAND);
        inscard.setText("");
        insLab.setCursor(Cursor.DEFAULT);
        insLab.setOnMouseClicked(null);

    }

    //TODO: When sensible input available: replace states with states of sc
    private enum states {INIT, ASSIGNED}
}
