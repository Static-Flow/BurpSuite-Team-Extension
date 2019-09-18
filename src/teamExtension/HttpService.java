package teamExtension;

import burp.IHttpService;

class HttpService implements IHttpService
{
    private final String host;
    private final int port;
    private final String protocol;

    HttpService() {
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
