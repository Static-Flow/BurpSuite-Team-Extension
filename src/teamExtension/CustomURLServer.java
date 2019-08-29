package teamExtension;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.util.Date;
import java.util.StringTokenizer;

public class CustomURLServer implements Runnable {

    private static final int port = 8888;
    private static final String newLine = "\r\n";
    private final SharedValues sharedValues;

    private ServerSocket socket;

    public CustomURLServer(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
    }

    @Override
    public void run() {
        try {
            socket = new ServerSocket(port);
            while (sharedValues.innerServerRunning) {
                Socket connection = socket.accept();
                try {
                    BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                    OutputStream out = new BufferedOutputStream(connection.getOutputStream());
                    PrintStream pout = new PrintStream(out);

                    // read first line of request
                    String request = in.readLine();
                    if (request == null) continue;

                    StringTokenizer tokenizer = new StringTokenizer(request);
                    String httpMethod = tokenizer.nextToken();
                    String httpQueryString = tokenizer.nextToken();
                    System.out.println(httpMethod + ":" + httpQueryString.substring(1));
                    try {
                        HttpRequestResponse httpRequestResponse = this.sharedValues.getGson().fromJson(
                                new String(Base64.getDecoder().decode(httpQueryString.substring(1))),
                                HttpRequestResponse.class);
                        System.out.println(httpRequestResponse.getHttpService().getHost());
                        this.sharedValues.getCallbacks().sendToRepeater(
                                httpRequestResponse.getHttpService().getHost(),
                                httpRequestResponse.getHttpService().getPort(),
                                httpRequestResponse.getHttpService().getProtocol()
                                        .equalsIgnoreCase("https"),
                                httpRequestResponse.getRequest(),
                                "BurpTC Link Payload");
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    // we ignore the rest
                    while (true) {
                        String ignore = in.readLine();
                        if (ignore == null || ignore.length() == 0) break;
                    }

                    if (!request.startsWith("GET ") ||
                            !(request.endsWith(" HTTP/1.0") || request.endsWith(" HTTP/1.1"))) {
                        // bad request
                        pout.print("HTTP/1.0 400 Bad Request" + newLine + newLine);
                    } else {
                        String response = "Link Processed!";

                        pout.print(
                                "HTTP/1.0 200 OK" + newLine +
                                        "Content-Type: text/plain" + newLine +
                                        "Date: " + new Date() + newLine +
                                        "Content-length: " + response.length() + newLine + newLine +
                                        response
                        );
                    }

                    pout.close();
                } catch (Exception tri) {
                    tri.printStackTrace();
                }
            }
        } catch (Throwable tr) {
            if (sharedValues.innerServerRunning) {
                System.err.println("Could not start server: " + tr);
            }
        }
    }

    ServerSocket getSocket() {
        return socket;
    }

}
