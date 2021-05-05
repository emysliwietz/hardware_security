package gui;

import Auto.Auto;
import Smartcard.Smartcard;
import javafx.fxml.FXML;
import javafx.scene.Cursor;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollBar;
import javafx.scene.control.TextArea;
import receptionTerminal.ReceptionTerminal;

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

    private enum states{INIT,ASSIGNED}
    private states state = states.INIT;
    private Smartcard sc = new Smartcard(new byte[4], new byte[8]); //TODO
    private Auto a = new Auto(new byte[4], new byte[8]);
    private ReceptionTerminal rt = new ReceptionTerminal(new byte[4], new byte[8]);


    public void insert(){
        insLab.setOnMouseClicked(null);
        insLab.setCursor(Cursor.DEFAULT);
        inscard.setText("");
        inscard.setCursor(Cursor.DEFAULT);
        display.setWrapText(true);
        ScrollBar scrollBarv = (ScrollBar)display.lookup(".scroll-bar:vertical");
        scrollBarv.setDisable(true);
        display.setText("Please specify which device you want to insert your card into.");
        left0.setText("Car");
        right0.setText("Reception");
        l0.setCursor(Cursor.HAND);
        r0.setCursor(Cursor.HAND);
        l0.setOnMouseClicked(event -> carStart());
        r0.setOnMouseClicked(event -> receptionAuth());
    }

    private void receptionAuth() {
        l0.setCursor(Cursor.DEFAULT);
        r0.setCursor(Cursor.DEFAULT);
        left0.setText("");
        right0.setText("");
        System.out.println("Authentication protocol");
        display.setText("");
        l0.setOnMouseClicked(null);
        r0.setOnMouseClicked(null);
        Thread t1 = new Thread(() -> sc.authReception(rt));
        Thread t2 = new Thread(() -> rt.cardAuthentication(sc));
        t1.start();
        t2.start();
        try {
            t1.join();
            t2.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        if (state == states.INIT){
            System.out.println("Car assignment");
            t1 = new Thread(() -> sc.carAssignment(rt));
            t2 = new Thread(() -> rt.carAssignment(sc));
            t1.start();
            t2.start();
            try {
                t1.join();
                t2.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            display.setText("Your car is: Fiat Multipla with plate HN J 5099");
            state = states.ASSIGNED;
            right2.setText("OK");
            r2.setCursor(Cursor.HAND);
            r2.setOnMouseClicked(event -> ok());
        } else {
            System.out.println("Car return");
            t1 = new Thread(() -> sc.carReturn(rt));
            t2 = new Thread(() -> rt.carReturn(sc));
            t1.start();
            t2.start();
            try {
                t1.join();
                t2.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            display.setText("Total kilometers driven: " + rt.kilometerage + "km\nPrice: "+ 0.15*rt.kilometerage +"€");
            state = states.INIT;
            right2.setText("OK");
            r2.setCursor(Cursor.HAND);
            r2.setOnMouseClicked(event -> ok());
        }
    }

    private void ok() {
        inscard.setText("Insert Card");
        inscard.setCursor(Cursor.HAND);
        right2.setText("");
        r2.setCursor(Cursor.DEFAULT);
        display.setText("Welcome! Please insert your card.");
        insLab.setCursor(Cursor.HAND);
        insLab.setOnMouseClicked(event -> insert());
    }

    private void carStart() {
        l0.setCursor(Cursor.DEFAULT);
        r0.setCursor(Cursor.DEFAULT);
        left0.setText("");
        right0.setText("");
        l0.setOnMouseClicked(null);
        r0.setOnMouseClicked(null);
        Thread t1 = new Thread(() -> sc.insert(a));
        Thread t2 = new Thread(() -> a.authenticateSmartCard(sc));
        t1.start();
        t2.start();
        try {
            t1.join();
            t2.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        if(state != states.ASSIGNED){
            display.setText("You need to have a car assigned first!");
            right2.setText("OK");
            r2.setCursor(Cursor.HAND);
            r2.setOnMouseClicked(event -> ok());
            return;
        }
        System.out.println("Car start");
        t1 = new Thread(() -> sc.kilometerageUpdate(a));
        t2 = new Thread(() -> a.kilometerageUpdate(sc));
        t1.start();
        t2.start();
        try {
            t1.join();
            t2.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        display.setText("Current mileage: 69");
        inscard.setText("Stop the car");
        insLab.setCursor(Cursor.HAND);
        insLab.setOnMouseClicked(event -> ok());
    }
}
