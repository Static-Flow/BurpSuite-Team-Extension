package burp;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpServer;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class SharedValues implements IProxyListener, IHttpListener {
    private URL teammateServerUrl;
    private int teammateServerPort;
    private int yourPort;
    private HttpServer server = null;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private IBurpExtenderCallbacks callbacks;
    private Gson gson;
    private boolean replayRequests = false;
    private boolean verboseDebug = false;

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
        server.createContext("/message", new PostHandler(stdout, callbacks,
                this));
        server.setExecutor(null);
        server.start();
        this.callbacks.registerProxyListener(this);
    }

    public void stopCommunication(){
        server.stop(0);
        stdout.println("Server stopped");
        this.callbacks.removeProxyListener(this);
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

    public void setReplayRequests(boolean replayRequests) {
        this.replayRequests = replayRequests;
    }

    public boolean getReplayRequests() {
        return replayRequests;
    }

    public void startMonitoringBurpTools() {
        this.callbacks.registerHttpListener(this);
    }

    public void stopMonitoringBurpTools() {
        this.callbacks.removeHttpListener(this);
    }


    public boolean getVerboseDebug() {
        return verboseDebug;
    }

    public void setVerboseDebug(boolean verboseDebug) {
        this.verboseDebug = verboseDebug;
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if(this.getVerboseDebug()){
            stdout.println("caught proxy request");
        }
        HttpRequestResponse reqResp = new HttpRequestResponse(message
                .getMessageInfo());
        sendHttpRequestResponse(reqResp);

    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest,
                                   IHttpRequestResponse messageInfo) {
        if(this.getVerboseDebug()){
            stdout.println("caught tool request");
        }
        HttpRequestResponse reqResp = new HttpRequestResponse(messageInfo);
        sendHttpRequestResponse(reqResp);
    }

    private void sendHttpRequestResponse(HttpRequestResponse reqResp) {
        URL url;
        try {
            url = this.getTeammateServerUrl();
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/json");
            Map<String, String> parameters = new HashMap<>();
            String jsonReqResp = this.gson.toJson(reqResp);
            if(this.getVerboseDebug()){
                stdout.println(jsonReqResp);
            }
            parameters.put("message", this.gson.toJson(reqResp));
            con.setDoOutput(true);
            DataOutputStream out = new DataOutputStream(con.getOutputStream());
            out.writeBytes(ParameterStringBuilder.getParamsString(parameters));
            out.flush();
            out.close();
            if(this.getVerboseDebug()) {
                stdout.println("sent request");
                stdout.println("Got response " + Integer.toString(con
                        .getResponseCode()));
            }
        } catch (IOException e) {
            stderr.println(e.getMessage());
        }
    }

}
