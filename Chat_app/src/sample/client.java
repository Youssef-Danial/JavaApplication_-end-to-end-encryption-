package sample;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class client extends Application {
    // initializing variables
    // the encryption and decryption are True by default
    private boolean encrytpion_stat = true;
    private boolean decyption_stat = true;
    private static DataInputStream dIn;
    private static DataOutputStream dOut;
    private static String client_name;
    private static Socket socket;
    private static SecretKey Client_Key;
    boolean isconnected = true;
    private static SecretKey client_key_temp;
    String text = "";
    // setting the AES
    AES Aes = new AES();
    // Encrypting and decrypting using the Cipher Class From Java
    private static byte[] AES_encrypt(String text, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        // Setting the Encryption Mode to AES ===> AES/ECB/NoPadding
        Cipher aes = Cipher.getInstance("AES");
        // mode Encryption because this is the encryption function
        aes.init(Cipher.ENCRYPT_MODE, key);
        // converting the Message to Bytes
        byte[] plaintext = text.getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = aes.doFinal(plaintext);
        // returning the Cipher text after encrypting it so it will be sent to all the clients connected
        // to the server
        return ciphertext;
    }

    private static String AES_decrypt(byte[] text, SecretKey key) {
        String stringplaintext = "";
        try {
            // setting the Cipher object from the Cipher class
            Cipher aes = null;
            // setting the Encryption mode AES ===> AES/ECB/NoPadding
            aes = Cipher.getInstance("AES");
            // setting the mode here we set it to DECRYPT_MODE we are in the decryption function
            aes.init(Cipher.DECRYPT_MODE, key);
            // setting the Chipher text to text we can remove this line and the code will work fine if we just
            // put Text in aes.doFinal(text)
            byte[] ciphertext = text;
            // decrypting the Cipher text
            byte[] plaintext = aes.doFinal(ciphertext);
            // converting the bytes to String
            stringplaintext = new String(plaintext, StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            System.out.println("The message received you can not decrypt it because the message is not encypted at the first place");
        } catch (BadPaddingException e) {
            System.out.println("Your key is not able to decrypt the data received from the Server");
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        // returning the text after decrypting it
        return stringplaintext;
    }

    // main function that is being called to run the client
    public static void main(String[] args) {
        try {
            // connecting the socket to the server
            socket = new Socket("localhost", 8000);
        } catch (IOException e) {
            e.printStackTrace();
        }
        // launching to the GUI because we are using JavaFx
        launch(args);
    }

    // Override function of start for the javafx GUI
    // most of the work are in the start function
    @Override
    public void start(Stage primaryStage) throws Exception {
        Parent root = FXMLLoader.load(getClass().getResource("sample.fxml"));
        // Creating a pane from VBox to contain the element of GUI
        VBox Root = new VBox();
        // Setting a title to the Stage
        // Making a label
        Label youssef = new Label("Made by Youssef_Danial_Elwi ID: 41810056");
        Label des = new Label("multi user chat application (end to end) encryption");
        // setting the title of the stage
        primaryStage.setTitle("YDE Chat");
        Scene Home = new Scene(Root, 400, 400);
        //setting padding between element
        Root.setSpacing(10);
        // Design is here
        //Button for closing
        //creating the first page to show to the client
        Button Signin = new Button("SignIn");
        Label user = new Label("Username (should be 5 or more char)");
        TextField Username = new TextField();
        Label pass = new Label("Key (should be 16 || 24 || 32 char)");
        TextField Encryption_key = new TextField();
        Label indicate = new Label();
        // Sign on Action
        Signin.setOnAction((event) -> {
            int keylength = Encryption_key.getText().length();
            // making sure that the client have entered right passwords or have received a password from pre sharing
            if (keylength == 16 || keylength == 24 || keylength == 32 || Encryption_key.isDisabled() && Username.getText().length() >= 5) {
               // if the Encryption key is disabled then no need to take the keys from the textfield
                if(!Encryption_key.isDisabled()){
                    setkey(Encryption_key.getText());
                 }
                // setting the name of the client
                client_name = Username.getText();
                // setting the buttons and labels
                Button Close = new Button("Close");
                TextField chat_type = new TextField();
                Button Send = new Button("Send");
                TextArea chatmain = new TextArea();
                Button refresh = new Button("Refresh");
                // making the textArea not editable
                chatmain.setEditable(false);
                //Setting the TextField to take input from the user to send it to the server
                //by making an action to the button
                Send.setOnAction((eventt) -> {
                    String messege = client_name + " : " + chat_type.getText();
                    // Clearing the Chat Field
                    chat_type.clear();
                    System.out.println("Your Messege is : " + messege + "\n");
                    // encrypting the messege before sending
                    // creating the byte messege
                    byte[] encryptedmessage = new byte[0];
                    try {
                        // this is because the user have the choice to encrypt the message before sending it
                        if (encrytpion_stat == true) {
                            // if the user is enabling the encryption this will call the encryption function and encrypt the message
                            encryptedmessage = AES_encrypt(messege, Client_Key);

                        } else {
                            // while if the user disable the encryption the message the message is being sent as it is
                            // sending unencrypted message
                            encryptedmessage = messege.getBytes(StandardCharsets.UTF_8);
                        }
                        // catching
                    } catch (NoSuchPaddingException e) {
                        e.printStackTrace();
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    } catch (InvalidKeyException e) {
                        e.printStackTrace();
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    } catch (IllegalBlockSizeException e) {
                        e.printStackTrace();
                    } catch (BadPaddingException e) {
                        e.printStackTrace();
                    }
                    try {
                        // setting the DataOuptutStream
                        dOut = new DataOutputStream(socket.getOutputStream());
                        // printing the message before sending it to the server
                        System.out.println("the message before sending to the server");
                        System.out.println(encryptedmessage);
                        dOut.writeInt(encryptedmessage.length); // write length of the message
                        dOut.write(encryptedmessage);           // write the message
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    // if there is no errors this message indicate that the message have been sent to the server
                    System.out.println("Messege have been Sent");
                    // setting an array of bytes called message to be used in receiving the messages from the server
                    byte[] message = null;
                    try {
                        //
                        dIn = new DataInputStream(socket.getInputStream());
                        int length = dIn.readInt();                    // read length of incoming message
                        if (length > 0) {
                            message = new byte[length];
                            dIn.readFully(message, 0, message.length); // read the message
                        }
                        System.out.println(message);
                        String receivedmessage = "";
                        if (decyption_stat == true) {
                            receivedmessage = AES_decrypt(message, Client_Key);
                        } else {
                            receivedmessage = new String(message, StandardCharsets.UTF_8);
                        }
                        if (receivedmessage != "") {
                            text = text + "\n" + receivedmessage;
                            System.out.println(text);
                            // showing the messeges in the text Area
                            chatmain.setText(text);
                            // to scroll down so the user do not bother himself with scrolling each time a message come
                            chatmain.setScrollTop(Double.MAX_VALUE);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                });
                refresh.setOnAction((eventt) -> {
                    // setting an array of bytes to receive the data from the server in it
                    // and then pass it to the AES decryption function
                    byte[] message = null;
                    try {
                        dIn = new DataInputStream(socket.getInputStream());
                        if (dIn.available() > 0) {
                            int length = dIn.readInt();                    // read length of incoming message
                            if (length > 0) {
                                message = new byte[length];
                                dIn.readFully(message, 0, message.length); // read the message
                            }
                            System.out.println(message);
                            String receivedmessage = "";
                            if (decyption_stat == true) {
                                receivedmessage = AES_decrypt(message, Client_Key);
                            } else {
                                receivedmessage = new String(message, StandardCharsets.UTF_8);
                            }
                            if (receivedmessage != "") {
                                text = text + "\n" + receivedmessage;
                                System.out.println(text);
                                // showing the messeges in the text Area
                                chatmain.setText(text);
                                // to scroll down so the user do not bother himself with scrolling each time a message come
                                chatmain.setScrollTop(Double.MAX_VALUE);
                            }
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }


                });
                // Creating a auto refreshing to receive messages from the server
                // by creating a thread at the client end
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        while (true && isconnected == true) {
                            refresh.fire();
                            try {
                                // this is a delay idk i made it to save resources
                                Thread.sleep(1000);
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                }).start();
                //Closing everything
                Close.setOnAction((eventt) -> {
                    isconnected = false;
                    try {
                        // closing the socket when the client close the chat application
                        socket.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    primaryStage.close();
                });
                // making button on or off for encryption before sending the messages
                Button encryption_state = new Button("Encryption");
                // by default the button will be green
                encryption_state.setStyle("-fx-background-color: #00FF00; ");
                encryption_state.setOnAction((eventt) -> {
                    // if encryption_stat is True
                    if (encrytpion_stat) {
                        // changing the state
                        encrytpion_stat = false;
                        // setting the color of the button to red
                        encryption_state.setStyle("-fx-background-color: #FF0000; ");
                    } else {
                        // changing the state
                        encrytpion_stat = true;
                        // setting the color of the button to red
                        encryption_state.setStyle("-fx-background-color: #00FF00; ");
                    }

                });
                // decrypting choice button
                Button decyption_state = new Button("Decryption");
                decyption_state.setStyle("-fx-background-color: #00FF00; ");
                decyption_state.setOnAction((eventt) -> {
                    // if decryption_stat is True
                    if (decyption_stat) {
                        decyption_stat = false;
                        // setting the color of the button to red
                        decyption_state.setStyle("-fx-background-color: #FF0000; ");
                    } else {
                        decyption_stat = true;
                        // setting the color of the button to red
                        decyption_state.setStyle("-fx-background-color: #00FF00; ");
                    }

                });
                //making pre shared key here in ths section
                // clearing the root from children to move from the sign in to the main chat
                Root.getChildren().clear();
                // adding the Children to the VBOX Pane
                Root.getChildren().addAll(youssef, des, chatmain, chat_type, Send, encryption_state, decyption_state, Close);
                // setting the scene to the stage
                primaryStage.setScene(Home);
                // showing the stage
                primaryStage.show();
            } else {
                // this Error will show up if the user type name wrong or the password as required
                indicate.setText("The name or the key is not Right");
            }
        });


        // now i will make a function that will send the numbers to the server
        // by making this an option so i will make a button
        Button share_key = new Button("Share your Key");
        Button receive_key_from_server = new Button("Receive the key");
        share_key.setOnAction((event) -> {
            int keylength = Encryption_key.getText().length();
            if (keylength == 16 || keylength == 24 || keylength == 32 || Encryption_key.isDisabled() && Username.getText().length() >= 5) {
                // setting the scene and pane and showing it to the user
                // getting the key from the user
                String keyfour = Encryption_key.getText().substring(0, 4);
                System.out.println("The four digits are : " + keyfour);

                // sending the key to the server
                // creating a button for the clients that want to receive a key from the server
                try {
                    // setting the connection
                    dOut = new DataOutputStream(socket.getOutputStream());
                    // waiting for 7 seconds to make sure that the message have been delivered to the
                    // making the key for the encryption
                    String tempkey = MSM(Integer.parseInt(keyfour), 6, 100);
                    tempkey = tempkey.substring(0, 16);
                    AES.setKey(tempkey);
                    // sending a sign to make the server know that it will receive a key coming
                    // setting an array of bytes so we can send it to the server
                    byte[] alercoming_key = "keycoming-880".getBytes(StandardCharsets.UTF_8);
                    System.out.println(alercoming_key.length);
                    dOut.writeInt(alercoming_key.length);
                    dOut.write(alercoming_key);
                    // after sending the key the server will be ready to receive a key from the client
                    // sending the keyfour that will contain 4 numbers that will be sent to the server
                    // and the server will make a key based on the four numbers
                    dOut.writeInt((keyfour.getBytes(StandardCharsets.UTF_8)).length);
                    dOut.write(keyfour.getBytes(StandardCharsets.UTF_8));
                    // now we will decrypt the key we have with the temp key and then send it to the server so
                    // the server by his own send it to the rest of the clients as a seed
                    // now receiving the key from the client
                    // encrypting the real key
                    byte[] realkey = AES.encrypt(Encryption_key.getText()).getBytes(StandardCharsets.UTF_8);
                    // now sending the key of encryption
                    dOut.writeInt(realkey.length);
                    dOut.write(realkey);
                    // now the real key have been sent to the Server
                    receive_key_from_server.fire();

                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });


        receive_key_from_server.setOnAction((event) -> {
            // the server by his own send it to the rest of the clients as a seeds
            while (true) {


                String Seed = receive_message();
                System.out.println(" the Seed "+ Seed);
                // if there is no message received then we did not get the seed and we should not continue
                // and instead keep looping until the seed is received
                if (Seed != "") {
                    // making the key for the encryption
                    String tempkey = MSM(Integer.parseInt(Seed), 6, 100);
                    tempkey = tempkey.substring(0, 16);
                    System.out.println("the MSM key generated " + tempkey);
                    AES.setKey(tempkey);
                    // making a thread to wait for 6 seconds to make sure to receive the real key
                    // to make sure that the Seed have been delivered to all the clients and then
                    // that the server have started deliever
                    // receiving the real key from the server
                    String receive_real_key = receive_message();
                    System.out.println("the real key "+receive_real_key);
                    // the real key have been set
                    // dercypting the real key with the temp key
                    System.out.println("client_key "+client_key_temp);
                    receive_real_key = AES.decrypt(receive_real_key);
                    System.out.println("the real key after decryption "+ receive_real_key);
                    setkey(receive_real_key);
                    System.out.println("key have been received");
                    // now the client does not have to enter a secret key
                    Encryption_key.setDisable(true);
                    // now the user can sign in without any problem
                    // giving an indication that the client have already received the key
                    pass.setText("key from pre sharing : Received : you can sign in");
                    // breaking from the loop after finishing
                    break;
                }

            }

        });
        Root.getChildren().

                addAll(youssef, des, user, Username, pass, Encryption_key, indicate, Signin, share_key, receive_key_from_server);
        primaryStage.setScene(Home);
        primaryStage.show();
    }

    // making a function to receive messages from the server
    private String receive_message() {
        while(true) {
            byte[] message = null;
            try {
                dIn = new DataInputStream(socket.getInputStream());
                if (dIn.available() > 0) {
                    int length = dIn.readInt();                    // read length of incoming message

                    if (length > 0) {
                        message = new byte[length];
                        dIn.readFully(message, 0, message.length); // read the message
                        System.out.println("receive message " + message);
                        String message_received = new String(message, StandardCharsets.UTF_8);
                        return message_received;
                    }

                }

            } catch (IOException e) {
                e.printStackTrace();
            }

        }

    }


    // random generating function Mid Square method
    // self made
    public static String MSM(int num, int count, int m) {
        int num_square = (int) Math.pow(num, 2);
        int newnumber = 0;
        String numstring = Integer.toString(num_square);
        while (numstring.length() < 6) {
            numstring = numstring + "0";
        }
        int length = numstring.length();
        if (count != 0 && length != 6) {
            String word1 = numstring.substring(0, length / 2);
            String word2 = numstring.substring(length / 2);
            String word3 = word1.substring(word1.length() / 2);
            String word4 = word2.substring(0, word2.length() / 2);
            word1 = word3 + word4;
            word1.replaceFirst("^0+(?!$)", "");
            newnumber = Integer.parseInt(word1);
            count = count - 1;
            // setting the Rn
            double Rn = ((double) newnumber / (double) m);
            return word1 + MSM(newnumber, count, m);
        }
        if (numstring.length() == 6 && count != 0) {
            numstring.replaceFirst("^0+(?!$)", "");
            String word = numstring.substring(0, length - 2);
            newnumber = Integer.parseInt(word);
            count = count - 1;
            return word + MSM(newnumber, count, m);
        }
        return "";
    }

    // this function to set the key that have been entered by the user
    public void setkey(String key) {
        Client_Key = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
    }

}