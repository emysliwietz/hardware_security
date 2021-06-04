package gui;

import Auto.Auto;
import db.Database;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;
import receptionTerminal.ReceptionTerminal;

import java.io.IOException;

public class SmartcardGUI extends Application {

    Auto a;
    ReceptionTerminal rt;


    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) throws IOException {
        Database db = new Database();
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
        FXMLLoader loader = new FXMLLoader(getClass().getResource("SmartcardGUI.fxml"));
        Parent root = loader.load();
        SmartcardGUIController controller = loader.getController();
        controller.setVars(a, rt, db);

        FXMLLoader cardLoader = new FXMLLoader(getClass().getResource("Smartcard.fxml"));
        Parent pcard = cardLoader.load();
        /*Stage card = new Stage();
        Scene card_scene = new Scene(pcard);
        card.setScene(card_scene);

        card.show();*/
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
        primaryStage.getIcons().add(new Image(SmartcardGUI.class.getResourceAsStream("icon.png")));
        primaryStage.show();
    }

}
