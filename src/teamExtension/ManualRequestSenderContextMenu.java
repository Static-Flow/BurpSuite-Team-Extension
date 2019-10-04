package teamExtension;

import burp.*;

import javax.swing.Timer;
import javax.swing.*;
import java.awt.*;
import java.net.URL;
import java.util.List;
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

    private Collection<? extends JMenuItem> createLinkMenu(IContextMenuInvocation invocation) {
        JMenuItem click = new JMenuItem("create link");
        click.addActionListener(e ->
                createLinkForSelectedRequests(invocation));
        ArrayList<JMenuItem> menuList = new ArrayList<>();
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
            new SwingWorker<Boolean, Void>() {
                @Override
                public Boolean doInBackground() {
                    JTabbedPane burpTab = ((JTabbedPane) sharedValues.getBurpPanel().getParent());
                    burpTab.setBackgroundAt(
                            burpTab.indexOfTab("Burp TC"),
                            new Color(0xff6633)
                    );
                    Timer timer = new Timer(3000, e -> {
                        if (burpTab.getBackground().equals(new Color(0x3C3F41))) {
                            //We are in dark mode
                            burpTab.setBackgroundAt(burpTab.indexOfTab("Burp TC"), new Color(0xBBBBBB));
                        } else {
                            burpTab.setBackgroundAt(burpTab.indexOfTab("Burp TC"), Color.black);
                        }

                    });
                    timer.setRepeats(false);
                    timer.start();
                    return Boolean.TRUE;
                }

                @Override
                public void done() {
                }
            }.execute();
        }

    }


    private Collection<? extends JMenuItem> creatCommentMenu(IContextMenuInvocation invocation) {
        JMenuItem menu = new JMenuItem("Comments");
        menu.addActionListener(e -> {
            System.out.println(invocation.getSelectedMessages().length);
            IHttpRequestResponse message = invocation.getSelectedMessages()[0];
            URL selectedRequestUrl = sharedValues.getExtensionHelpers().analyzeRequest(message).getUrl();
            HttpRequestResponse requestResponseWithComments = sharedValues.getRequestCommentModel()
                    .findRequestWithCommentsByUrl(selectedRequestUrl);
            if (requestResponseWithComments != null)
                displayCommentsFrame(requestResponseWithComments);
            else
                displayCommentsFrame(new HttpRequestResponse(message));
        });
        ArrayList<JMenuItem> menuList = new ArrayList<>();
        menuList.add(menu);
        return menuList;
    }

    private void displayCommentsFrame(HttpRequestResponse requestResponse) {
        new CommentFrame(sharedValues.getCallbacks(), requestResponse, sharedValues.getServerConnection().getYourName());
    }

    private Collection<? extends JMenuItem> createSharingMenu(String topMenuName, IContextMenuInvocation invocation) {
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
        ArrayList<JMenuItem> menuList = new ArrayList<>();
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
                menues.addAll(createSharingMenu("Share Request", invocation));
                menues.addAll(creatCommentMenu(invocation));
            } else if (Objects.equals(IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS, invocation.getInvocationContext())) {
                menues.addAll(createSharingMenu("Share Intruder Payload", invocation));

            } else if (Objects.equals(IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST, invocation.getInvocationContext())) {
                menues.addAll(createSharingMenu("Share Repeater Payload", invocation));
            }
        }
        System.out.println("Size: " + menues.size());
        return menues;
    }
}
