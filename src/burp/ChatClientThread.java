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
                DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd " +
                        "HH:mm:ss.SSS");
                System.out.println(dateFormat.format(System.currentTimeMillis
                        ()));
            	this.client.handle(this.streamIn.readLine());
            }
            catch (IOException iOException) {
                DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd " +
                        "HH:mm:ss.SSS");
                System.out.println(dateFormat.format(System.currentTimeMillis
                        ()));
                System.out.println("Listening error: " + iOException.getMessage());
                StackTraceElement[] elements = iOException.getStackTrace();
                for (int i = 0; i < elements.length; i++) {
                  StackTraceElement s = elements[i];
                  System.out.println("\tat " + s.getClassName() + "." + s.getMethodName()
                      + "(" + s.getFileName() + ":" + s.getLineNumber() + ")");
                }
                this.client.stop();
            }
        } while (true);
    }
}
