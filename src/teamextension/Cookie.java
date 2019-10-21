package teamextension;

import burp.ICookie;

import java.util.Date;

class Cookie implements ICookie {

    private String domain;
    private String path;
    private Date expiration;
    private String name;
    private String value;

    public Cookie() {
    }

    public Cookie(ICookie copyCookie) {
        domain = copyCookie.getDomain();
        path = copyCookie.getPath();
        expiration = copyCookie.getExpiration();
        name = copyCookie.getName();
        value = copyCookie.getValue();
    }

    @Override
    public String getDomain() {
        return domain;
    }

    @Override
    public String getPath() {
        return path;
    }

    @Override
    public Date getExpiration() {
        return expiration;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getValue() {
        return value;
    }
}
