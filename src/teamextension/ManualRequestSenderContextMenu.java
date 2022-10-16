package teamextension;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

import javax.net.ssl.HttpsURLConnection;
import javax.swing.Timer;
import javax.swing.*;
import java.awt.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
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
        HttpRequestResponse httpRequestResponse;
        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS) { //intruder
            this.sharedValues.getCallbacks().printOutput(Arrays.toString(invocation.getSelectionBounds()));
            httpRequestResponse = new HttpRequestResponse(invocation.getSelectedMessages()[0]);
            BurpTCMessage intruderMessage = new BurpTCMessage(
                    httpRequestResponse, MessageType.INTRUDER_MESSAGE, sendingContext == CONTEXT_SEND_TO_GROUP ?
                    SharedValues.ROOM :
                    sendingContextArgument);
            sharedValues.getClient().sendMessage(intruderMessage);
        } else if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) { //repeater
            httpRequestResponse = new HttpRequestResponse(invocation.getSelectedMessages()[0]);
            BurpTCMessage repeaterMessage = new BurpTCMessage(
                    httpRequestResponse, MessageType.REPEATER_MESSAGE, sendingContext == CONTEXT_SEND_TO_GROUP ?
                    SharedValues.ROOM :
                    sendingContextArgument);
            sharedValues.getClient().sendMessage(repeaterMessage);
        } else {                                                                                                //sending generics
            for (IHttpRequestResponse reqResp : invocation.getSelectedMessages()) {
                httpRequestResponse = new HttpRequestResponse(reqResp);
                this.sharedValues.getCallbacks().printOutput(httpRequestResponse.toString());
                if (reqResp.getResponse() != null) {
                    //is bottom level request
                    BurpTCMessage burpTCMessage = new BurpTCMessage(
                            httpRequestResponse, MessageType.BURP_MESSAGE, sendingContext == CONTEXT_SEND_TO_GROUP ?
                            SharedValues.ROOM : sendingContextArgument);
                    sharedValues.getClient().sendMessage(burpTCMessage);
                } else {
                    for (IHttpRequestResponse iHttpRequestResponse : sharedValues.getCallbacks().getSiteMap(
                            reqResp.getHttpService().getProtocol() + "://" + reqResp.getHttpService().getHost())) {
                        if (iHttpRequestResponse.getResponse() != null) {
                            BurpTCMessage burpTCMessage = new BurpTCMessage(
                                    new HttpRequestResponse(iHttpRequestResponse), MessageType.BURP_MESSAGE, sendingContext == CONTEXT_SEND_TO_GROUP ?
                                    SharedValues.ROOM : sendingContextArgument);
                            sharedValues.getClient().sendMessage(burpTCMessage);
                        }
                    }
                }
            }
        }

    }


    private void createLinkForSelectedRequests(IContextMenuInvocation invocation) {
        HttpRequestResponse httpRequestResponse =
                new HttpRequestResponse();
        for (IHttpRequestResponse message : invocation.getSelectedMessages()) {
            new SwingWorker<Boolean, Void>() {
                @Override
                public Boolean doInBackground() {
                    DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
                    LocalDateTime localDate = LocalDateTime.now();
                    httpRequestResponse.setRequest(message.getRequest());
                    httpRequestResponse.setHttpService(message.getHttpService());
                    try {
                        sharedValues.getSharedLinksModel().addBurpMessage(httpRequestResponse, dtf.format(localDate));
                        visuallyUpdateBurpTCTab();
                    } catch (IOException e) {
                        sharedValues.getCallbacks().printError(e.getMessage());
                    }
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

        CommentFrame commentSession = new CommentFrame(sharedValues,
                requestResponse,
                sharedValues.getClient().getUsername());
        sharedValues.getRequestCommentModel().addCommentSession(commentSession);
    }

    private Collection<? extends JMenuItem> createLinkMenu(IContextMenuInvocation invocation) {
        JMenu menu = new JMenu("Create Link");
        JMenuItem compressedLink = new JMenuItem("Create Compressed Link");
        compressedLink.addActionListener(e ->
                createLinkForSelectedRequests(invocation));
        menu.add(compressedLink);

        JMenuItem shortenedLink = new JMenuItem("Create Shortened Link");
        shortenedLink.addActionListener(e ->
                createLinkForSelectedRequestsUsingServer(invocation));
        menu.add(shortenedLink);

        ArrayList<JMenuItem> menuList = new ArrayList<>();
        menuList.add(menu);
        return menuList;
    }

    private void createLinkForSelectedRequestsUsingServer(IContextMenuInvocation invocation) {
        HttpRequestResponse httpRequestResponse =
                new HttpRequestResponse();
        for (IHttpRequestResponse message : invocation.getSelectedMessages()) {
            new SwingWorker<Boolean, Void>() {
                @Override
                public Boolean doInBackground() {
                    DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
                    LocalDateTime localDate = LocalDateTime.now();
                    httpRequestResponse.setRequest(message.getRequest());
                    httpRequestResponse.setHttpService(message.getHttpService());

                    String requestToShorten =
                            sharedValues.getGson().toJson(httpRequestResponse,
                            HttpRequestResponse.class);
                    sharedValues.getCallbacks().printOutput(requestToShorten);

                    try {
                        URL url =
                                new URL("https://" + sharedValues.getClient().getServerAddress() +
                                        "/shortener?key="+sharedValues.getUrlShortenerApiKey());
                        HttpsURLConnection con = sharedValues.getUnsafeURL(url);
                        con.setRequestMethod("POST");
                        con.setRequestProperty("Content-Type", "application/json; utf-8");
                        con.setDoOutput(true);


                        OutputStream os = con.getOutputStream();
                        byte[] input = requestToShorten.getBytes(StandardCharsets.UTF_8);
                        os.write(input, 0, input.length);

                        BufferedReader br = new BufferedReader(
                                new InputStreamReader(con.getInputStream(),
                                        StandardCharsets.UTF_8));
                        StringBuilder response = new StringBuilder();
                        String responseLine;
                        while ((responseLine = br.readLine()) != null) {
                            sharedValues.getCallbacks().printOutput(
                                    "Line: "+responseLine);
                            response.append(responseLine.trim());
                        }
                        sharedValues.getCallbacks().printOutput(
                                "Response: "+response.toString());
                        sharedValues.getSharedLinksModel().addServerMadeLink(response.toString(), dtf.format(localDate));
                        visuallyUpdateBurpTCTab();

                    } catch (IOException | NoSuchAlgorithmException | KeyManagementException e) {
                        sharedValues.getCallbacks().printError(e.getMessage());
                    }
                    return Boolean.TRUE;
                }

                @Override
                public void done() {
                    //we don't need to do any cleanup so this is empty
                }
            }.execute();
        }
    }

    private void visuallyUpdateBurpTCTab() {
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
        if (Objects.equals(IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST , invocation.getInvocationContext())||
                Objects.equals(IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST, invocation.getInvocationContext()) ||
                Objects.equals(IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE, invocation.getInvocationContext()) ||
                Objects.equals(IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE, invocation.getInvocationContext())) {
            menues.addAll(createLinkMenu(invocation));
        }
        if (sharedValues.getClient() != null && sharedValues.getClient().isConnected() && sharedValues.getBurpPanel().inRoom()) {
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
