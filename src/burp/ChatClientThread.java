package burp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.text.DateFormat;
import java.text.SimpleDateFormat;

class ChatClientThread extends Thread {
    private Socket socket = null;
    private ServerConnector client = null;
    private BufferedReader streamIn = null;
    private PrintWriter stdErr = null;

    public ChatClientThread(ServerConnector serverConnector, Socket socket, PrintWriter printWriter) {
        this.client = serverConnector;
        this.socket = socket;
        this.stdErr = printWriter;
        this.open();
        this.start();
    }

    public void open() {
        try {
            this.streamIn = new BufferedReader(new InputStreamReader(this.socket.getInputStream
                    ()));
        }
        catch (IOException iOException) {
            System.out.println("Error getting input stream: " + iOException);
            this.client.stop();
        }
    }

    public void close() {
        try {
            if (this.streamIn != null) {
                this.streamIn.close();
            }
        }
        catch (IOException iOException) {
            System.out.println("Error closing input stream: " + iOException);
        }
    }

    @Override
    public void run() {
        byte[] readBuffer = new byte[5000];
        do {
            try {
            	this.client.handle(this.streamIn.readLine());
            }
            catch (IOException iOException) {
                System.out.println("Listening error: " + iOException.getMessage());
                this.client.stop();
            }
        } while (true);
    }
}
