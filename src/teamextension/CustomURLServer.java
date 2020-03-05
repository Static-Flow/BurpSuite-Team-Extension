package teamextension;

import com.google.gson.JsonObject;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.StringTokenizer;
import java.util.zip.GZIPInputStream;

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


    private ArrayList fromBytesToString(byte[] data) {
        ArrayList<Integer> values = new ArrayList<>();
        for(byte b : data){
           values.add((int) b);
        }
        return values;
    }

    private String decompress(byte[] compressed) throws IOException {
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(compressed);
            GZIPInputStream gis = new GZIPInputStream(bis);
            BufferedReader br = new BufferedReader(new InputStreamReader(gis, StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
                sb.append("\n");
            }
            br.close();
            gis.close();
            bis.close();
            String strippedJson = sb.toString();

            this.sharedValues.getCallbacks().printOutput(
                    "StrippedJson: " + strippedJson);
            String[] strippedJsonByDelimiter =
                    strippedJson.split(new String(new byte[]{127}));
            for (String jsonPiece : strippedJsonByDelimiter) {
                this.sharedValues.getCallbacks().printOutput("Piece: "+ jsonPiece);
            }
            JsonObject httpService = new JsonObject();
            httpService.addProperty("host",strippedJsonByDelimiter[2].trim());
            httpService.addProperty("port",strippedJsonByDelimiter[3].trim());
            httpService.addProperty("protocol",strippedJsonByDelimiter[4].trim());
            JsonObject mainJson = new JsonObject();
            mainJson.add("request",
                    this.sharedValues.getGson().newBuilder().create().toJsonTree(fromBytesToString(strippedJsonByDelimiter[0].getBytes())));
            mainJson.add("response",
                    this.sharedValues.getGson().newBuilder().create().toJsonTree(fromBytesToString(strippedJsonByDelimiter[1].getBytes())));
            mainJson.add("httpService",httpService);

            return mainJson.toString();

        } catch (NumberFormatException e){
            sharedValues.getCallbacks().printError("Decompress: " +
                    e.getMessage());
            return "";
        }

    }


    private void parseCustomMessage(String httpQueryString) {
        try {
            byte[] base64Decoded =
                    Base64.getDecoder().decode(httpQueryString.substring(1));
            String decompressedJson =
                    decompress(base64Decoded);
            this.sharedValues.getCallbacks().printOutput(
                    "Decompressed: " + decompressedJson);
            HttpRequestResponse httpRequestResponse = this.sharedValues.getGson().fromJson(decompressedJson,
                    HttpRequestResponse.class);
            this.sharedValues.getCallbacks().sendToRepeater(
                    httpRequestResponse.getHttpService().getHost(),
                    httpRequestResponse.getHttpService().getPort(),
                    httpRequestResponse.getHttpService().getProtocol()
                            .equalsIgnoreCase("https"),
                    httpRequestResponse.getRequest(),
                    "BurpTC Link Payload");
        } catch (Exception e) {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            e.printStackTrace(pw);
            sharedValues.getCallbacks().printError("ParseCustomMessage: " +
                    sw);
        }
    }

    ServerSocket getSocket() {
        return socket;
    }

}
