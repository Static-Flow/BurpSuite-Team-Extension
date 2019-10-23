package teamextension;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import javax.swing.Timer;
import javax.swing.*;
import java.awt.*;
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
        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS) { //intruder
            this.sharedValues.getCallbacks().printOutput(Arrays.toString(invocation.getSelectionBounds()));
            httpRequestResponse = new HttpRequestResponse(invocation.getSelectedMessages()[0]);
            BurpTCMessage intruderMessage = new BurpTCMessage(
                    httpRequestResponse, MessageType.INTRUDER_MESSAGE, sendingContext == CONTEXT_SEND_TO_GROUP ?
                    SharedValues.ROOM :
                    sendingContextArgument, null);
            sharedValues.getClient().sendMessage(intruderMessage);
        } else if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) { //repeater
            IHttpRequestResponse requestResponse =
                    invocation.getSelectedMessages()[0];
            createHttpRequestResponse(httpRequestResponse, requestResponse);
            BurpTCMessage repeaterMessage = new BurpTCMessage(
                    httpRequestResponse, MessageType.REPEATER_MESSAGE, sendingContext == CONTEXT_SEND_TO_GROUP ?
                    SharedValues.ROOM :
                    sendingContextArgument, null);
            sharedValues.getClient().sendMessage(repeaterMessage);
        } else {                                                                                                //sending generics
            HttpRequestResponse finalHttpRequestResponse = httpRequestResponse;
            new SwingWorker<Boolean, Void>() {
                @Override
                public Boolean doInBackground() {
                    for (IHttpRequestResponse reqResp : invocation.getSelectedMessages()) {
                        if (reqResp.getResponse() != null) {
                            sendMessage(reqResp);
                        } else {
                            IRequestInfo req = sharedValues.getCallbacks().getHelpers()
                                    .analyzeRequest(reqResp.getHttpService(),
                                            reqResp.getRequest());
                            IHttpRequestResponse[] requests = sharedValues.getCallbacks().getSiteMap(
                                    req.getUrl().getProtocol() + "://" +
                                            req.getUrl().getHost() + req.getUrl()
                                            .getPath());
                            for (IHttpRequestResponse reqRep : requests) {
                                sendMessage(reqRep);
                            }
                        }
                    }
                    return Boolean.TRUE;
                }

                private void sendMessage(IHttpRequestResponse reqResp) {
                    finalHttpRequestResponse.setRequest(reqResp.getRequest());
                    finalHttpRequestResponse.setResponse(reqResp.getResponse());
                    finalHttpRequestResponse.setHttpService(reqResp.getHttpService());
                    sharedValues.getCallbacks().printOutput(finalHttpRequestResponse.getHttpService().getHost());
                    BurpTCMessage burpTCMessage = new BurpTCMessage(
                            finalHttpRequestResponse, MessageType.BURP_MESSAGE,
                            sendingContext == CONTEXT_SEND_TO_GROUP ?
                                    SharedValues.ROOM :
                                    sendingContextArgument,
                            null);
                    sharedValues.getClient().sendMessage(burpTCMessage);
                }

                @Override
                public void done() {
                    //we don't need to do any cleanup so this is empty
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
                            burpTab.indexOfTab(SharedValues.EXTENSION_NAME),
                            new Color(0xff6633)
                    );
                    Timer timer = new Timer(3000, e -> {
                        if (burpTab.getBackground().equals(new Color(0x3C3F41))) {
                            //We are in dark mode
                            burpTab.setBackgroundAt(burpTab.indexOfTab(SharedValues.EXTENSION_NAME), new Color(0xBBBBBB));
                        } else {
                            burpTab.setBackgroundAt(burpTab.indexOfTab(SharedValues.EXTENSION_NAME), Color.black);
                        }

                    });
                    timer.setRepeats(false);
                    timer.start();
                    return Boolean.TRUE;
                }

                @Override
                public void done() {
                    //we don't need to do any cleanup so this is empty
                }
            }.execute();
        }

    }


    private Collection<? extends JMenuItem> creatCommentMenu(IContextMenuInvocation invocation) {
        JMenuItem menu = new JMenuItem("Comments");
        menu.addActionListener(e -> {
            HttpRequestResponse message = new HttpRequestResponse(invocation.getSelectedMessages()[0]);
            HttpRequestResponse requestResponseWithComments = sharedValues.getRequestCommentModel()
                    .findRequestResponseWithComments(message);
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
        if (sharedValues.getClient().isConnected() && sharedValues.getBurpPanel().inRoom()) {
            new CommentFrame(sharedValues, requestResponse,
                    sharedValues.getClient().getUsername());
        }
    }

    private Collection<? extends JMenuItem> createSharingMenu(String topMenuName, IContextMenuInvocation invocation) {
        JMenu menu = new JMenu(topMenuName);
        JMenuItem toGroupMenuItem = new JMenuItem("To Group");
        toGroupMenuItem.addActionListener(e ->
                sendSelectedRequests(invocation, CONTEXT_SEND_TO_GROUP, null));
        menu.add(toGroupMenuItem);
        JMenu toTeammateMenu = new JMenu("To Teammate");
        ArrayList<String> teammembers =
                this.sharedValues.getRoomMembersListModel().getRoomMembers();
        for (String teamMember : teammembers) {
            if (!teamMember.equals(sharedValues.getClient().getUsername())) {
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
            this.sharedValues.getCallbacks().printOutput("here");
            menues.addAll(createLinkMenu(invocation));
        }
        if (sharedValues.getBurpPanel().inRoom()) {
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
        return menues;
    }
}
