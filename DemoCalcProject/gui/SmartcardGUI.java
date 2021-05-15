package gui;

import Auto.Auto;
import Smartcard.Smartcard;
import db.Database;
import javafx.application.Application;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.effect.Effect;
import javafx.scene.effect.Glow;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.HBox;
import javafx.scene.media.Media;
import javafx.scene.media.MediaPlayer;
import javafx.scene.media.MediaView;
import javafx.scene.web.WebView;
import javafx.stage.Stage;
import receptionTerminal.ReceptionTerminal;

import java.io.IOException;

public class SmartcardGUI extends Application {

    Smartcard sc;
    Auto a;
    ReceptionTerminal rt;

    /*Label ins = (Label)loader.getNamespace().get("insLab");
    Label l0 = (Label)loader.getNamespace().get("left0");
    Label l1 = (Label)loader.getNamespace().get("left1");
    Label l2 = (Label)loader.getNamespace().get("left2");
    Label r0 = (Label)loader.getNamespace().get("right0");
    Label r1 = (Label)loader.getNamespace().get("right1");
    Label r2 = (Label)loader.getNamespace().get("right2");
    @FXML
    TextArea display = (TextArea)loader.getNamespace().get("display");*/

    public static void main(String[] args) {
        //gui.launch();
        //Thread t1 = new Thread(() -> Application.launch(SmartcardGUI.class, args));
        //t1.start();
        launch(args);
    }


    /*public void init(Smartcard sc,
                     Auto a,
                     ReceptionTerminal rt) {

    }*/

    @Override
    public void start(Stage primaryStage) throws IOException {
        Database db = new Database();
        rt = db.generateTerminal();
        a = db.generateAuto();
        sc = db.generateCard();
        FXMLLoader loader = new FXMLLoader(getClass().getResource("SmartcardGUI.fxml"));
        Parent root = loader.load();
        SmartcardGUIController controller = loader.getController();
        controller.setVars(sc, a, rt);

        FXMLLoader cardLoader = new FXMLLoader(getClass().getResource("Smartcard.fxml"));
        Parent pcard = cardLoader.load();
        Stage card = new Stage();
        Scene card_scene = new Scene(pcard);
        card.setScene(card_scene);

        card.show();
        /*MediaView media = (MediaView)loader.getNamespace().get("media");
        /*HBox hb = new HBox();
        Button b = new Button("Hallo");*/
        /*MediaPlayer mp = new MediaPlayer(new Media(this.getClass().getResource("juggle.mp4").toExternalForm()));
        media.setMediaPlayer(mp);
        mp.setAutoPlay(true);
        mp.setCycleCount(MediaPlayer.INDEFINITE);*/
        Scene s = new Scene(root);
        primaryStage.setScene(s);
        primaryStage.setTitle("test");
        primaryStage.setResizable(false);
        s.setOnMouseReleased(event ->
                System.out.println(event.getSceneX()));
        primaryStage.show();
    }

}
