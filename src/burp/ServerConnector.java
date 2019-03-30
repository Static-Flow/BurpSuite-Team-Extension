package burp;

import com.google.gson.JsonObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class ServerConnector
implements Runnable {
    private Socket socket = null;
    private Thread thread = null;
    private BufferedReader console = null;
    private PrintWriter  streamOut = null;
    private ChatClientThread client = null;
    private PrintWriter stdErr = null;
    private String yourName = "";
    private SharedValues sharedValues;
    private BlockingQueue<String> messg;

    public ServerConnector(String string, int n, String string2, PrintWriter printWriter, SharedValues sharedValues) {
        System.out.println("Establishing connection. Please wait ...");
        this.messg = new LinkedBlockingQueue<>(1);
        this.yourName = string2;
        this.sharedValues = sharedValues;
        this.stdErr = printWriter;
        try {
            this.socket = new Socket(string, n);
            System.out.println("Connected: " + this.socket);
            this.start();
        }
        catch (UnknownHostException unknownHostException) {
            System.out.println("Host unknown: " + unknownHostException.getMessage());
        }
        catch (IOException iOException) {
            System.out.println("Unexpected exception: " + iOException.getMessage());
        }
    }

    @Override
    public void run() {
        while (this.thread != null) {
            if (this.messg.size() <= 0) continue;
            System.out.println("Inside messg count" + String.valueOf(this.messg.size()));
            try {
                this.streamOut.println(this.messg.take());
                this.streamOut.flush();
            }
            catch (Exception exception) {
                System.out.println(exception.getMessage());
            }
        }
    }

    public void sendMessage(String string) {
        try {
        	this.messg.put(string);
        	System.out.println("Outside messg count" + String.valueOf(this.messg.size()));
        } catch(InterruptedException e) {
        	System.out.println(e.getMessage());
        }
    }

    public void handle(String string) {
        System.out.println("handling message: " + string);
        if (string != null && !string.equalsIgnoreCase("received")) {
            HttpRequestResponse httpRequestResponse = this.sharedValues
                    .getGson().fromJson(string.substring(string.indexOf(':') + 1), HttpRequestResponse.class);
            this.sharedValues.getCallbacks().addToSiteMap(httpRequestResponse);
        }
    }

    public void start() throws IOException {
        this.console = new BufferedReader(new InputStreamReader(System.in));
        this.streamOut = new PrintWriter(this.socket
                .getOutputStream
                (),true);
        JsonObject senderSocket = new JsonObject();
        senderSocket.addProperty("name", this.yourName);
        senderSocket.addProperty("room", "dev");
        senderSocket.addProperty("mode", "sender");
        this.streamOut.println(senderSocket);
        if (this.thread == null) {
            this.client = new ChatClientThread(this, this.socket, this.stdErr);
            this.thread = new Thread(this);
            this.thread.start();
        }
    }


    public void stop() {
        if (this.thread != null) {
            this.thread.stop();
            this.thread = null;
        }
        try {
            if (this.console != null) {
                this.console.close();
            }
            if (this.streamOut != null) {
                this.streamOut.close();
            }
            if (this.socket != null) {
                this.socket.close();
            }
        }
        catch (IOException iOException) {
            System.out.println("Error closing ...");
        }
        this.client.close();
        this.client.stop();
    }
}
