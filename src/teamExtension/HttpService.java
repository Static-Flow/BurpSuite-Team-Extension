package teamExtension;

import burp.IHttpService;

public class HttpService implements IHttpService
{
    private final String host;
    private final int port;
    private final String protocol;

    public HttpService() {
        host = "";
        port = 0;
        protocol = "";
    }

    HttpService(IHttpService copy) {
        this.host = copy.getHost();
        this.port = copy.getPort();
        this.protocol = copy.getProtocol();
    }

    @Override
    public String getHost() {
        return host;
    }

    @Override
    public int getPort() {
        return port;
    }

    @Override
    public String getProtocol() {
        return protocol;
    }
}
