package burp;

import com.google.gson.JsonObject;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.concurrent.BlockingQueue;

public class ServerWriteThread  implements Runnable{

    private BlockingQueue<String> messageQueue;
    private PrintWriter streamOut = null;
    private boolean exit;

    public ServerWriteThread(Socket serverSocket, String username,
                             String serverPassword, BlockingQueue<String> messageQueue) {
        this.exit = false;
        try {
            this.messageQueue = messageQueue;
            this.streamOut = new PrintWriter(serverSocket.getOutputStream(), true);
            //this.initConnection(username, serverPassword);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void initConnection(String username, String serverPassword) {
        JsonObject senderSocket = new JsonObject();
        senderSocket.addProperty("name", username);
        senderSocket.addProperty("room", "dev");
        senderSocket.addProperty("password", serverPassword);
        this.streamOut.println(senderSocket);
        this.streamOut.flush();
    }

    public void stop() {
        exit = true;
    }

    @Override
    public void run() {
        while (!exit) {
            if (!this.messageQueue.isEmpty()) {
                try {
                    String message = this.messageQueue.take();
                    System.out.println("Inside messg count: " + this.messageQueue.size());
                    this.streamOut.println(message);
                    this.streamOut.flush();
                    if (message.equalsIgnoreCase("bye")) break;
                } catch (Exception exception) {
                    System.out.println(exception.getMessage());
                }
            }
        }
    }
}
