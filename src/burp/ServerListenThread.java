package burp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;

public class ServerListenThread implements Runnable {

    private BufferedReader streamIn;
    private SharedValues sharedValues;

    public ServerListenThread(Socket socket, SharedValues sharedValues){
        try {
            this.streamIn = new BufferedReader(new InputStreamReader(socket.getInputStream
                    ()));
            this.sharedValues = sharedValues;
        }
        catch (IOException iOException) {
            System.out.println("Error getting input stream: " + iOException);
        }
    }

    @Override
    public void run() {
        do {
            try {
                String message = this.streamIn.readLine();
                System.out.println(message);
                if(message.startsWith("roommates")){
                    String currentUsers = message.split(":")[1];
                    for(String user : currentUsers.split(",")) {
                        System.out.println(user+":"+this.sharedValues.getServerConnection().getYourName().equalsIgnoreCase(user));
                        if(!this.sharedValues.getServerConnection().getYourName().equalsIgnoreCase(user)) {
                            System.out.println("new User");
                            this.sharedValues.getServerListModel().add(user);
                        }
                    }
                } else if(message.startsWith("leavingroommate")){
                    String leavingUser = message.split(":")[1];
                    this.sharedValues.getServerListModel().remove(leavingUser);
                } else{
                    HttpRequestResponse httpRequestResponse = this.sharedValues
                            .getGson().fromJson(message.substring(message.indexOf(':') + 1), HttpRequestResponse.class);
                    this.sharedValues.getCallbacks().addToSiteMap(httpRequestResponse);
                }
            }
            catch (IOException iOException) {
                System.out.println("Listening error: " + iOException.getMessage());
                break;
            }
        } while (true);
    }
}
