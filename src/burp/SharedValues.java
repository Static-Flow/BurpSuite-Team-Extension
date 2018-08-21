package burp;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpServer;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.*;
import java.util.HashMap;
import java.util.Map;

public class SharedValues implements IProxyListener {
    private URL teammateServerUrl;
    private int teammateServerPort;
    private int yourPort;
    private HttpServer server = null;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private IBurpExtenderCallbacks callbacks;
    private Gson gson;

    public SharedValues(IBurpExtenderCallbacks callbacks){
        this.teammateServerUrl = null;
        this.teammateServerPort = 0;
        if (stdout == null && stderr == null) {
            stdout = new PrintWriter(callbacks.getStdout(), true);
            stderr = new PrintWriter(callbacks.getStderr(), true);
        }
        this.callbacks = callbacks;
        this.gson = new Gson();

    }

    public void startCommunication(){
        try {
            server = HttpServer.create(new InetSocketAddress(this.getYourPort
                    ()), 0);
        } catch (IOException e) {
            stderr.println(e.getMessage());
        }
        System.out.println("server started at " + yourPort);
        server.createContext("/message", new PostHandler(stdout, callbacks));
        server.setExecutor(null);
        server.start();
        this.callbacks.registerProxyListener(this);
    }

    public void stopCommunication(){
        server.stop(0);
        this.callbacks.unloadExtension();
    }

    public int getYourPort() {
        return yourPort;
    }

    public void setYourPort(int yourPort) {
        this.yourPort = yourPort;
    }

    public PrintWriter getStdout() {
        return stdout;
    }

    public PrintWriter getStderr() {
        return stderr;
    }

    public Gson getGson() {
        return gson;
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }


    public URL getTeammateServerUrl() {
        return teammateServerUrl;
    }

    public void setTeammateServerUrl(URL teammateServerUrl) {
        this.teammateServerUrl = teammateServerUrl;
    }

    public int getTeammateServerPort() {
        return teammateServerPort;
    }

    public void setTeammateServerPort(int teammateServerPort) {
        this.teammateServerPort = teammateServerPort;
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        stdout.println("caught request");
        HttpRequestResponse reqResp = new HttpRequestResponse(message
                .getMessageInfo());
        URL url;
        try {
            url = this.getTeammateServerUrl();
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/json");
            Map<String, String> parameters = new HashMap<>();
            String jsonReqResp = this.gson.toJson(reqResp);
            stdout.println(jsonReqResp);
            parameters.put("message", this.gson.toJson(reqResp));
            stdout.println(parameters.get("message"));
            con.setDoOutput(true);
            DataOutputStream out = new DataOutputStream(con.getOutputStream());
            out.writeBytes(ParameterStringBuilder.getParamsString(parameters));
            out.flush();
            out.close();
            stdout.println("sent request");
            stdout.println("Got response "+ Integer.toString(con
                    .getResponseCode()));
        } catch (MalformedURLException e) {
            stderr.println(e.getMessage());
        } catch (ProtocolException e) {
            stderr.println(e.getMessage());
        } catch (IOException e) {
            stderr.println(e.getMessage());
        }

    }
}
