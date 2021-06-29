import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class ServerWork extends Thread {
    // Using threads because this is a small project
    // there is no huge number of users
    private final Socket clientsocket;
    private final Server server;
    DataInputStream dIn;
    // the constructor of the class taking the Server and the Client socket
    public ServerWork(Server server, Socket clientsocket) {
        this.clientsocket = clientsocket;
        this.server = server;
    }

    @Override
    public void run() {
        try {
            if (clientsocket.isConnected()) {
                handleclientSocket();
            } else {
                interrupt();
            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void handleclientSocket() throws IOException, InterruptedException {
        System.out.println("Entered the function");
        // to be looping in until the client socket is disconnected
        while (clientsocket.isConnected()) {
            byte[] message = null;
            try {
                dIn = new DataInputStream(clientsocket.getInputStream());
                int length = dIn.readInt();
                // read length of incoming message
                if (length > 0) {
                    message = new byte[length];
                    dIn.readFully(message, 0, message.length); // read the message
                }
                System.out.println("Messege received");
                String messagenotbyte = new String(message, StandardCharsets.UTF_8);
                System.out.println(messagenotbyte);
                // this condition is for pre-sharing key
                if(messagenotbyte.equals("keycoming-880")){
                    // now we will receive the seed and pass it to all the clients
                    message = receive_message().getBytes(StandardCharsets.UTF_8);
                    System.out.println("===============================");
                    System.out.println("this should be the seed "+message);
                    // messaging the seed too all the clients
                    message_to_all_clients(message);
                    // then receiving the real key from the client
                    message = receive_message().getBytes(StandardCharsets.UTF_8);

                    // then the if statement end and the code will continue and will send the key to all clients
                }
                // sending the messege to the clients
                message_to_all_clients(message);
                // this should close the connection of the client disconnects
                if (clientsocket.isClosed()) {
                    interrupt();
                    dIn.close();
                    clientsocket.close();
                    break;
                }
                // if the user disconnect from the server there will be an error and when catching it
                // closing the thread and removing the ServerWork object from the list
            } catch (IOException e) {
                interrupt();
                // this is to remove the client after s/he disconnect from the server
                server.getClientList().remove(this);
                System.out.println("Client Disconnected");
                // e.printStackTrace();
                break;
            }
            // if Client Socket is closed this message should show up
            if (clientsocket.isClosed()) {
                System.out.println("Client Disconnected");
                break;
            }


        }

    }

    private void message_to_all_clients(byte[] message) {
        // taking the list of Clients
        List<ServerWork> clientlist = server.getClientList();
        for (ServerWork client : clientlist) {
            // We are using this loop to send messages between all the clients
            client.Send(message);
        }
    }

    // this function to send messages to the client
    private void Send(byte[] message) {
        try {
            // sending the message
            System.out.println("messages sent  "+new String(message, StandardCharsets.UTF_8));
            DataOutputStream dOut = new DataOutputStream(clientsocket.getOutputStream());
            dOut.writeInt(message.length); // write length of the message
            dOut.write(message);
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("Messege have been sent to Client");
    }

    // making a function to receive messages from the server
    private String receive_message() {
        byte[] message = null;
        try {
            dIn = new DataInputStream(clientsocket.getInputStream());
            if (dIn.available() > 0) {
                int length = dIn.readInt();                    // read length of incoming message
                if (length > 0) {
                    message = new byte[length];
                    dIn.readFully(message, 0, message.length); // read the message
                }
                String message_received = new String(message, StandardCharsets.UTF_8);
                return message_received;
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
        return "";
    }

}
