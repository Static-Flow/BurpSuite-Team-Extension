package teamextension;

import burp.IHttpService;

public class HttpService implements IHttpService
{
    private final String host;
    private final int port;
    private final String protocol;

    HttpService(IHttpService copy) {
        this.host = copy.getHost();
        this.port = copy.getPort();
        this.protocol = copy.getProtocol();
    }

    @Override
    public String getHost() {
        if(host == null){
            return "";
        }
        return host;
    }

    @Override
    public int getPort() {
        return port;
    }

    @Override
    public String getProtocol() {
        if(protocol == null){
            return "";
        }
        return protocol;
    }
}
