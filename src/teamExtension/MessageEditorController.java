package teamExtension;

import burp.IHttpService;
import burp.IMessageEditorController;

public class MessageEditorController implements IMessageEditorController {

    private IHttpService httpService;
    private byte[] request;
    private byte[] response;

    MessageEditorController() {
    }

    MessageEditorController(IHttpService httpService, byte[] request, byte[] response) {
        this.httpService = httpService;
        this.request = request;
        this.response = response;
    }


    @Override
    public IHttpService getHttpService() {
        return this.httpService;
    }

    @Override
    public byte[] getRequest() {
        return this.request;
    }

    @Override
    public byte[] getResponse() {
        return this.response;
    }
}
