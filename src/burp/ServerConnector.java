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


    public ServerConnector(String serverAddress, int serverPort, String yourName,
                           PrintWriter printWriter, SharedValues sharedValues) {
        System.out.println("Establishing connection. Please wait ...");
        this.messg = new LinkedBlockingQueue<>(1);
        this.yourName = yourName;
        this.sharedValues = sharedValues;
        this.stdErr = printWriter;
        try {
            this.socket = new Socket(serverAddress, serverPort);
            ServerWriteThread writer = new ServerWriteThread(this.socket,
                    this.yourName, this.messg);
            ServerListenThread listener = new ServerListenThread(this.socket,
                    sharedValues);
            Thread writerThread = new Thread(writer);
            Thread listenerThread = new Thread(listener);
            listenerThread.start();
            writerThread.start();

            System.out.println("Connected: " + this.socket);
//            this.start();
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

    public String getYourName() {
        return yourName;
    }

    public Socket getSocket() {
        return socket;
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
        if(string == null) {
        	this.stop();
        }
        else if (!string.equalsIgnoreCase("received")) {
            System.out.println("handling message: " + string);
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
        System.out.println("stopping connection");
        try {
            if (this.socket != null) {
                this.socket.close();
            }
            if (this.console != null) {
                this.console.close();
            }
            if (this.streamOut != null) {
                this.streamOut.close();
            }
            this.client.close();
            this.client.stop();
            if (this.thread != null) {
                this.thread.stop();
                this.thread = null;
            }
        }
        catch (IOException iOException) {
            System.out.println("Error closing ...");
        }
    }

    public void leave() {
        System.out.println("leaving server");
        this.sendMessage("bye");
    }
}
