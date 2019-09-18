package teamExtension;

import burp.*;

import javax.swing.*;
import java.util.*;

public class ManualRequestSenderContextMenu implements IContextMenuFactory {

    private static final byte CONTEXT_SEND_TO_GROUP = 0;
    private static final byte CONTEXT_SEND_TO_INDIVIDUAL = 1;
    private final SharedValues sharedValues;

    public ManualRequestSenderContextMenu(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
    }

    private void sendSelectedRequests(IContextMenuInvocation invocation,
                                      byte sendingContext,
                                      String sendingContextArgument) {
        HttpRequestResponse httpRequestResponse =
                new HttpRequestResponse();
        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS) {
            System.out.println(Arrays.toString(invocation.getSelectionBounds()));
            IHttpRequestResponseWithMarkers markers = (IHttpRequestResponseWithMarkers) invocation.getSelectedMessages()[0];
            System.out.println(markers.getRequestMarkers());
            httpRequestResponse = new HttpRequestResponse(invocation.getSelectedMessages()[0]);
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
            HttpRequestResponse finalHttpRequestResponse = httpRequestResponse;
            new SwingWorker<Boolean, Void>() {
                @Override
                public Boolean doInBackground() {
                    for (IHttpRequestResponse reqResp : invocation.getSelectedMessages()) {
                        IRequestInfo req =
                                sharedValues.getExtensionHelpers()
                                        .analyzeRequest(reqResp.getHttpService(),
                                                reqResp.getRequest());
                        System.out.println(req.getUrl());
                        System.out.println(sharedValues.getCallbacks().getSiteMap(
                                req.getUrl().getProtocol() + "://" +
                                        req.getUrl().getHost() + req.getUrl()
                                        .getPath()).length);
                        IHttpRequestResponse[] requests = sharedValues.getCallbacks().getSiteMap(
                                req.getUrl().getProtocol() + "://" +
                                        req.getUrl().getHost() + req.getUrl()
                                        .getPath());
                        for (IHttpRequestResponse reqRep : requests) {
                            finalHttpRequestResponse.setRequest(reqRep.getRequest());
                            finalHttpRequestResponse.setResponse(reqRep.getResponse());
                            finalHttpRequestResponse.setHttpService(reqRep.getHttpService());
                            BurpTCMessage intruderMessage = new BurpTCMessage(
                                    finalHttpRequestResponse, MessageType.BURP_MESSAGE, sharedValues.getServerConnection().getCurrentRoom(),
                                    sendingContext == CONTEXT_SEND_TO_GROUP ? "room" : sendingContextArgument,
                                    null);
                            sharedValues.getServerConnection().sendMessage(intruderMessage);
                        }
                    }
                    return Boolean.TRUE;
                }

                @Override
                public void done() {
                }
            }.execute();
        }
    }

    private void createHttpRequestResponse(HttpRequestResponse httpRequestResponse, IHttpRequestResponse requestResponse) {
        httpRequestResponse.setRequest(requestResponse.getRequest());
        httpRequestResponse.setResponse(requestResponse.getResponse());
        httpRequestResponse.setHttpService(requestResponse.getHttpService());
    }

    private ArrayList createLinkMenu(IContextMenuInvocation invocation) {
        JMenuItem click = new JMenuItem("create link");
        click.addActionListener(e ->
                createLinkForSelectedRequests(invocation));
        ArrayList menuList = new ArrayList();
        menuList.add(click);
        return menuList;
    }

    private void createLinkForSelectedRequests(IContextMenuInvocation invocation) {
        HttpRequestResponse httpRequestResponse =
                new HttpRequestResponse();
        for (IHttpRequestResponse message : invocation.getSelectedMessages()) {
            httpRequestResponse.setRequest(message.getRequest());
            httpRequestResponse.setHttpService(message.getHttpService());
            this.sharedValues.getSharedLinksModel().addBurpMessage(httpRequestResponse);
            System.out.println(Base64.getEncoder().encodeToString(this.sharedValues.getGson()
                    .toJson(httpRequestResponse).getBytes()));
        }

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
        ArrayList<JMenuItem> menues = new ArrayList<>();
        if (Objects.equals(IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST, invocation.getInvocationContext())) {
            System.out.println("here");
            menues.addAll(createLinkMenu(invocation));
        }
        if (sharedValues.getServerConnection() != null &&
                !sharedValues.getServerConnection().getCurrentRoom().equals(sharedValues.getServerConnection().SERVER)) {
            if (Arrays.asList(IContextMenuInvocation.CONTEXT_PROXY_HISTORY,
                    IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE,
                    IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE).contains(invocation.getInvocationContext())) {
                menues.addAll(createMenu("Share Request", invocation));
            } else if (Objects.equals(IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS, invocation.getInvocationContext())) {
                menues.addAll(createMenu("Share Intruder Payload", invocation));

            } else if (Objects.equals(IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST, invocation.getInvocationContext())) {
                menues.addAll(createMenu("Share Repeater Payload", invocation));
            }
        }
        System.out.println("Size: " + menues.size());
        return menues;
    }
}
