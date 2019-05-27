package burp;

import com.google.gson.JsonObject;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.concurrent.BlockingQueue;

public class ServerWriteThread  implements Runnable{

    private BlockingQueue<String> messageQueue;
    private PrintWriter streamOut = null;

    public ServerWriteThread(Socket serverSocket, String username,
                             BlockingQueue<String> messageQueue){
        try {
            this.messageQueue = messageQueue;
            this.streamOut = new PrintWriter(serverSocket
                    .getOutputStream
                            (),true);
            this.initConnection(username);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void initConnection(String username){
        JsonObject senderSocket = new JsonObject();
        senderSocket.addProperty("name", username);
        senderSocket.addProperty("room", "dev");
        senderSocket.addProperty("mode", "sender");
        this.streamOut.println(senderSocket);
        this.streamOut.flush();
    }

    @Override
    public void run() {
        while(true){
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
