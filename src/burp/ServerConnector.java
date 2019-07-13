package burp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class ServerConnector {
    private PrintWriter stdErr;
    private String serverAddress;
    private int serverPort;
    private String yourName;
    private String serverPassword;
    private SharedValues sharedValues;
    private BlockingQueue<String> messg;
    private ServerWriteThread writer;
    private ServerListenThread listener;
    private Thread listenerThread;


    public ServerConnector(String serverAddress, int serverPort, String yourName,
                           String serverPassword, PrintWriter printWriter,
                           SharedValues sharedValues) {
        System.out.println("Establishing connection. Please wait ...");
        this.messg = new LinkedBlockingQueue<>(1);
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
        this.serverPassword = serverPassword;
        this.yourName = yourName;
        this.sharedValues = sharedValues;
        this.stdErr = printWriter;

    }

    public void authenticate()
            throws LoginFailedException, IOException {
        Socket socket = new Socket(this.serverAddress, this.serverPort);
        PrintWriter streamOut = new PrintWriter(socket.getOutputStream(), true);
        BufferedReader streamIn = new BufferedReader(new InputStreamReader(socket.getInputStream
                ()));
        BurpTCMessage loginMessage = new BurpTCMessage(null,
                MessageType.LOGIN_MESSAGE, "dev", "room", null);
        loginMessage.setAuthentication(this.getServerPassword());
        loginMessage.setSendingUser(this.getYourName());
        streamOut.println(this.sharedValues.getGson().toJson(loginMessage));
        streamOut.flush();
        BurpTCMessage loginResponse = this.sharedValues.getGson().fromJson(
                streamIn.readLine(), BurpTCMessage.class);
        System.out.println(loginResponse);
        if (loginResponse.getAuthentication().trim().equals("SUCCESS")) {
            this.writer = new ServerWriteThread(socket,
                    this.yourName, this.serverPassword, this.messg);
            this.listener = new ServerListenThread(socket,
                    sharedValues);
            Thread writerThread = new Thread(writer);
            this.listenerThread = new Thread(listener);
            listenerThread.start();
            writerThread.start();
            System.out.println("Connected: " + socket);
        } else {
            throw new LoginFailedException();
        }
    }

    public String getYourName() {
        return yourName;
    }

    public String getServerPassword() {
        return this.serverPassword;
    }

    public void sendMessage(BurpTCMessage message) {
        try {
            message.setAuthentication(this.getServerPassword());
            message.setSendingUser(this.getYourName());
            this.messg.put(this.sharedValues.getGson().toJson(message));
            System.out.println("Outside messg count" + this.messg.size());
        } catch(InterruptedException e) {
        	System.out.println(e.getMessage());
        }
    }

    public void leave() {
        System.out.println("leaving server");
        BurpTCMessage leavingMessage = new BurpTCMessage(null,
                MessageType.QUIT_MESSAGE, "dev", "room", null);
        this.sendMessage(leavingMessage);
        cutTheHardLine();
    }

    public Thread getListener() {
        return this.listenerThread;
    }

    public void cutTheHardLine() {
        this.writer.stop();
        this.listener.stop();
    }

    public void muteMember(String selectedValue) {
        BurpTCMessage muteMessage = new BurpTCMessage(null, MessageType.MUTE_MESSAGE, "dev",
                selectedValue, null);
        this.sendMessage(muteMessage);
    }

    public void unmuteMember(String selectedValue) {
        BurpTCMessage unmuteMessage = new BurpTCMessage(null, MessageType.UNMUTE_MESSAGE, "dev",
                selectedValue, null);
        this.sendMessage(unmuteMessage);
    }
}
