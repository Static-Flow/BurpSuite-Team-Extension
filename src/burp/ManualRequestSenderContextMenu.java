package burp;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ManualRequestSenderContextMenu implements IContextMenuFactory {

    private static final byte CONTEXT_SEND_TO_GROUP = 0;
    private static final byte CONTEXT_SEND_TO_INDIVIDUAL = 1;
    private SharedValues sharedValues;

    public ManualRequestSenderContextMenu(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
    }

    public void sendSelectedRequests(IContextMenuInvocation invocation,
                                     byte sendingContext,
                                     String sendingContextArgument) {
        HttpRequestResponse httpRequestResponse =
                new HttpRequestResponse();
        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS) {
            IHttpRequestResponse requestResponse =
                    invocation.getSelectedMessages()[0];
            httpRequestResponse.setRequest(requestResponse.getRequest());
            httpRequestResponse.setResponse(requestResponse.getResponse());
            httpRequestResponse.setHttpService(requestResponse.getHttpService());
            if (sendingContext == CONTEXT_SEND_TO_INDIVIDUAL) {
                sharedValues.getServerConnection().sendMessage(
                        "Intruder:To:" + sendingContextArgument + ":" +
                                sharedValues.getGson()
                                        .toJson(httpRequestResponse));
            } else {
                sharedValues.getServerConnection().sendMessage(
                        "Intruder:" + sharedValues.getGson()
                                .toJson(httpRequestResponse));
            }
        } else if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
            IHttpRequestResponse requestResponse =
                    invocation.getSelectedMessages()[0];
            createHttpRequestResponse(httpRequestResponse, requestResponse);
            if (sendingContext == CONTEXT_SEND_TO_INDIVIDUAL) {
                sharedValues.getServerConnection().sendMessage(
                        "Repeater:To:" + sendingContextArgument + ":" +
                                sharedValues.getGson()
                                        .toJson(httpRequestResponse));
            } else {
                sharedValues.getServerConnection().sendMessage(
                        "Repeater:" + sharedValues.getGson()
                                .toJson(httpRequestResponse));
            }
        } else {
            for (IHttpRequestResponse reqResp : invocation.getSelectedMessages()) {
                IRequestInfo req =
                        this.sharedValues.getExtentionHelpers()
                                .analyzeRequest(reqResp.getHttpService(),
                                        reqResp.getRequest());
                System.out.println(req.getUrl());
                System.out.println(this.sharedValues.getCallbacks().getSiteMap(
                        req.getUrl().getProtocol() + "://" +
                                req.getUrl().getHost() + req.getUrl()
                                .getPath()).length);
                IHttpRequestResponse[] requests = this.sharedValues.getCallbacks().getSiteMap(
                        req.getUrl().getProtocol() + "://" +
                                req.getUrl().getHost() + req.getUrl()
                                .getPath());
                for (IHttpRequestResponse reqRep : requests) {
                    httpRequestResponse.setRequest(reqRep.getRequest());
                    httpRequestResponse.setResponse(reqRep.getResponse());
                    httpRequestResponse.setHttpService(reqRep.getHttpService());
                    if (sendingContext == CONTEXT_SEND_TO_GROUP) {
                        sharedValues.getServerConnection().sendMessage(
                                sharedValues.getGson().toJson(httpRequestResponse));
                    } else {
                        sharedValues.getServerConnection().sendMessage(
                                "To:" + sendingContextArgument + ":" +
                                        sharedValues.getGson()
                                                .toJson(httpRequestResponse));
                    }
                }
            }
        }
    }

    private void createHttpRequestResponse(HttpRequestResponse httpRequestResponse, IHttpRequestResponse requestResponse) {
        httpRequestResponse.setRequest(requestResponse.getRequest());
        httpRequestResponse.setResponse(requestResponse.getResponse());
        httpRequestResponse.setHttpService(requestResponse.getHttpService());
    }

    private ArrayList createMenu(String topMenuName, IContextMenuInvocation invocation) {
        JMenu menu = new JMenu(topMenuName);
        JMenuItem toGroupMenuItem = new JMenuItem("To Group");
        toGroupMenuItem.addActionListener(e ->
                sendSelectedRequests(invocation, CONTEXT_SEND_TO_GROUP, null));
        menu.add(toGroupMenuItem);
        JMenu toTeammateMenu = new JMenu("To Teammate");
        ArrayList<String> teammembers =
                this.sharedValues.getServerListModel().getServersMembers();
        for (String teamMember : teammembers) {
            JMenuItem teammate1MenuItem = new JMenuItem(teamMember);
            teammate1MenuItem.addActionListener(e ->
                    sendSelectedRequests(invocation,
                            CONTEXT_SEND_TO_INDIVIDUAL, teamMember));
            toTeammateMenu.add(teammate1MenuItem);
        }
        menu.add(toTeammateMenu);
        ArrayList menuList = new ArrayList();
        menuList.add(menu);
        return menuList;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        if (Arrays.asList(IContextMenuInvocation.CONTEXT_PROXY_HISTORY,
                IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE,
                IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE).contains(invocation.getInvocationContext())) {
            return createMenu("Forward Request", invocation);
        } else if (Arrays.asList(IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS)
                .contains(invocation.getInvocationContext())) {
            return createMenu("Share Intruder Payload", invocation);

        } else if (Arrays.asList(IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST)
                .contains(invocation.getInvocationContext())) {
            return createMenu("Share Repeater Payload", invocation);

        } else {
            return null;
        }
    }
}
