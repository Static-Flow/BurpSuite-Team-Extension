package teamExtension;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class ManualRequestSenderContextMenu implements IContextMenuFactory {

    private static final byte CONTEXT_SEND_TO_GROUP = 0;
    private static final byte CONTEXT_SEND_TO_INDIVIDUAL = 1;
    private SharedValues sharedValues;

    public ManualRequestSenderContextMenu(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
    }

    private void sendSelectedRequests(IContextMenuInvocation invocation,
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
            BurpTCMessage intruderMessage = new BurpTCMessage(
                    httpRequestResponse, MessageType.INTRUDER_MESSAGE, sharedValues.getServerConnection().getCurrentRoom(),
                    sendingContext == CONTEXT_SEND_TO_INDIVIDUAL ? sendingContextArgument : "room",
                    null);
            sharedValues.getServerConnection().sendMessage(intruderMessage);
        } else if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
            IHttpRequestResponse requestResponse =
                    invocation.getSelectedMessages()[0];
            createHttpRequestResponse(httpRequestResponse, requestResponse);
            BurpTCMessage intruderMessage = new BurpTCMessage(
                    httpRequestResponse, MessageType.REPEATER_MESSAGE, sharedValues.getServerConnection().getCurrentRoom(),
                    sendingContext == CONTEXT_SEND_TO_INDIVIDUAL ? sendingContextArgument : "room",
                    null);
            sharedValues.getServerConnection().sendMessage(intruderMessage);
        } else {
            for (IHttpRequestResponse reqResp : invocation.getSelectedMessages()) {
                IRequestInfo req =
                        this.sharedValues.getExtensionHelpers()
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
                    BurpTCMessage intruderMessage = new BurpTCMessage(
                            httpRequestResponse, MessageType.BURP_MESSAGE, sharedValues.getServerConnection().getCurrentRoom(),
                            sendingContext == CONTEXT_SEND_TO_GROUP ? "room" : sendingContextArgument,
                            null);
                    sharedValues.getServerConnection().sendMessage(intruderMessage);
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
            if (!teamMember.equals(sharedValues.getServerConnection().getYourName())) {
                JMenuItem teammate1MenuItem = new JMenuItem(teamMember);
                teammate1MenuItem.addActionListener(e ->
                        sendSelectedRequests(invocation,
                                CONTEXT_SEND_TO_INDIVIDUAL, teamMember));
                toTeammateMenu.add(teammate1MenuItem);
            }
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
        } else if (Objects.equals(IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS, invocation.getInvocationContext())) {
            return createMenu("Share Intruder Payload", invocation);

        } else if (Objects.equals(IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST, invocation.getInvocationContext())) {
            return createMenu("Share Repeater Payload", invocation);

        } else {
            return null;
        }
    }
}
