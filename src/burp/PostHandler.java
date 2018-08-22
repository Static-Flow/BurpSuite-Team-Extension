package burp;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.*;
import java.net.URLDecoder;
import java.util.stream.Collectors;

/**
 * Created by Tanner on 8/19/2018.
 */
public class PostHandler implements HttpHandler {


    private final PrintWriter stdout;
    private IBurpExtenderCallbacks callbacks;
    private Gson gson;
    private SharedValues sharedValues;

    public PostHandler(PrintWriter stdout, IBurpExtenderCallbacks callbacks, SharedValues sharedValues) {
        this.stdout = stdout;
        this.callbacks = callbacks;
        this.gson = new Gson();
        this.sharedValues = sharedValues;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String requestMethod = exchange.getRequestMethod();
        if (requestMethod.equalsIgnoreCase("POST")) {
            if(this.sharedValues.getVerboseDebug()){
                stdout.println("Got request");
            }
            String body = new BufferedReader(
                    new InputStreamReader(
                            exchange.getRequestBody()
                    )
            ).lines().collect(Collectors.joining("\n"));
            body = URLDecoder.decode(body,"UTF-8");
            body = body.substring(body.indexOf("=")+1);
            HttpRequestResponse receivedReaResp = gson.fromJson(
                    URLDecoder.decode(body, "UTF-8"),
                    HttpRequestResponse.class);
            if(this.sharedValues.getVerboseDebug()) {
                stdout.println("marshaled");
                stdout.println(receivedReaResp);
            }
            if(this.sharedValues.getReplayRequests() == true){
                this.callbacks.makeHttpRequest(receivedReaResp.getHttpService
                        (),receivedReaResp.getRequest());
            }else {
                this.callbacks.addToSiteMap(receivedReaResp);
            }
            exchange.getResponseHeaders().set("Content-Type", "text/plain");
            exchange.sendResponseHeaders(200, 0);
            OutputStream responseBody = exchange.getResponseBody();
            responseBody.write("Received".getBytes());
            responseBody.close();
        }
    }

}
