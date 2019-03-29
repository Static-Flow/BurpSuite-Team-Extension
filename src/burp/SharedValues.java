/*
 * Decompiled with CFR 0.139.
 * 
 * Could not load the following classes:
 *  burp.HttpRequestResponse
 *  burp.IBurpExtenderCallbacks
 *  burp.IHttpRequestResponse
 *  burp.IInterceptedProxyMessage
 *  burp.IProxyListener
 *  burp.ServerConnector
 *  com.google.gson.Gson
 */
package burp;

import burp.HttpRequestResponse;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;
import burp.ServerConnector;
import com.google.gson.Gson;
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URL;

public class SharedValues
implements IProxyListener {
    private URL teammateServerUrl = null;
    private int teammateServerPort = 0;
    private int yourPort;
    private ServerConnector serverConnector = null;
    private HttpServer server = null;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private IBurpExtenderCallbacks callbacks;
    private Gson gson;

    public SharedValues(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        if (this.stdout == null && this.stderr == null) {
            this.stdout = new PrintWriter(iBurpExtenderCallbacks.getStdout(), true);
            this.stderr = new PrintWriter(iBurpExtenderCallbacks.getStderr(), true);
        }
        this.callbacks = iBurpExtenderCallbacks;
        this.gson = new Gson();
    }

    public void startCommunication() {
        this.callbacks.registerProxyListener((IProxyListener)this);
    }

    public void stopCommunication() {
        this.server.stop(0);
        this.callbacks.unloadExtension();
    }

    public ServerConnector getServerConnection() {
        return this.serverConnector;
    }

    public void setServerConnection(ServerConnector serverConnector) {
        this.serverConnector = serverConnector;
    }

    public int getYourPort() {
        return this.yourPort;
    }

    public void setYourPort(int n) {
        this.yourPort = n;
    }

    public PrintWriter getStdout() {
        return this.stdout;
    }

    public PrintWriter getStderr() {
        return this.stderr;
    }

    public Gson getGson() {
        return this.gson;
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return this.callbacks;
    }

    public URL getTeammateServerUrl() {
        return this.teammateServerUrl;
    }

    public void setTeammateServerUrl(URL uRL) {
        this.teammateServerUrl = uRL;
    }

    public int getTeammateServerPort() {
        return this.teammateServerPort;
    }

    public void setTeammateServerPort(int n) {
        this.teammateServerPort = n;
    }

    public void processProxyMessage(boolean bl, IInterceptedProxyMessage iInterceptedProxyMessage) {
        this.stdout.println("caught request: "+bl);
        if(!bl) {
	        HttpRequestResponse httpRequestResponse = new HttpRequestResponse(iInterceptedProxyMessage.getMessageInfo());
	        this.getServerConnection().sendMessage(this.gson.toJson(httpRequestResponse));
        }
    }
}
