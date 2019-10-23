package teamextension;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.util.Date;
import java.util.StringTokenizer;

public class CustomURLServer implements Runnable {

    private static final String NEW_LINE = "\r\n";
    private final SharedValues sharedValues;

    private ServerSocket socket;

    public CustomURLServer(SharedValues sharedValues) throws IOException {
        this.sharedValues = sharedValues;
        socket = new ServerSocket(0);
    }

    @Override
    public void run() {
        try {
            while (sharedValues.innerServerRunning) {
                handleConnection(socket.accept());
            }
        } catch (Exception tr) {
            if (sharedValues.innerServerRunning) {
                sharedValues.getCallbacks().printError("Could not start server: " + tr);
            }
        }
    }

    private void handleConnection(Socket connection) {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            OutputStream out = new BufferedOutputStream(connection.getOutputStream());
            PrintStream pout = new PrintStream(out);

            // read first line of request
            String request = in.readLine();
            if (request != null) {

                StringTokenizer tokenizer = new StringTokenizer(request);
                String httpMethod = tokenizer.nextToken();
                String httpQueryString = tokenizer.nextToken();
                sharedValues.getCallbacks().printOutput(httpMethod + ":" + httpQueryString.substring(1));
                parseCustomMessage(httpQueryString);
                // we ignore the rest
                while (true) {
                    String ignore = in.readLine();
                    if (ignore == null || ignore.length() == 0) break;
                }

                if (!request.startsWith("GET ") ||
                        !(request.endsWith(" HTTP/1.0") || request.endsWith(" HTTP/1.1"))) {
                    // bad request
                    pout.print("HTTP/1.0 400 Bad Request" + NEW_LINE + NEW_LINE);
                } else {
                    String response = "Link Processed!";

                    pout.print(
                            "HTTP/1.0 200 OK" + NEW_LINE +
                                    "Content-Type: text/plain" + NEW_LINE +
                                    "Date: " + new Date() + NEW_LINE +
                                    "Content-length: " + response.length() + NEW_LINE + NEW_LINE +
                                    response
                    );
                }

                pout.close();
            }
        } catch (Exception tri) {
            sharedValues.getCallbacks().printError(tri.getMessage());
        }
    }

    private void parseCustomMessage(String httpQueryString) {
        try {
            HttpRequestResponse httpRequestResponse = this.sharedValues.getGson().fromJson(
                    new String(Base64.getDecoder().decode(httpQueryString.substring(1))),
                    HttpRequestResponse.class);
            this.sharedValues.getCallbacks().sendToRepeater(
                    httpRequestResponse.getHttpService().getHost(),
                    httpRequestResponse.getHttpService().getPort(),
                    httpRequestResponse.getHttpService().getProtocol()
                            .equalsIgnoreCase("https"),
                    httpRequestResponse.getRequest(),
                    "BurpTC Link Payload");
        } catch (Exception e) {
            sharedValues.getCallbacks().printError(e.getMessage());
        }
    }

    ServerSocket getSocket() {
        return socket;
    }

}
