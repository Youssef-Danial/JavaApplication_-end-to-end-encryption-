import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;


public class Server extends Thread {
    // setting socket for the client and the server
    static Socket socket;
    static ServerSocket server = null;
    // the port
    static int port = 8000;
    // making a list with the server work to make them be able to access each other
    private ArrayList<ServerWork> ClientList = new ArrayList<ServerWork>();

    // making this to make other eserverwokr be able to access each other
    public List<ServerWork> getClientList() {
        return ClientList;
    }

    @Override
    public void run() {
        try {
            server = new ServerSocket(port);
            System.out.println("Server have Started Successfully ");
            while (true) {
                System.out.println("Waiting for Clients to Connect");
                //accepting the the connection from the client
                //Setting a Socket to listen to the Client
                Socket clientsocket = server.accept();
                System.out.println("Client connected Successfully");
                System.out.println("Client Information: " + clientsocket);
                // passing the server to make each ServerWork be able to access each other inside
                // each work
                ServerWork work = new ServerWork(this, clientsocket);
                ClientList.add(work);
                // to start the ServerWork to listen to the client and pass data to it
                work.start();

            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
