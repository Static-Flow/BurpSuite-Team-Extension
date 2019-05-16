package burp;

import javax.swing.*;
import java.util.ArrayList;

public class ServerListModel extends AbstractListModel<String> {

    private ArrayList<String> serversList;
    private ArrayList<String> serversMembers;
    private boolean serverConnected;

    public ServerListModel(){
        this.serverConnected = false;
        this.serversList = new ArrayList<>();
        this.serversMembers = new ArrayList<>();
    }

    public void setServerConnected(boolean isConnected){
        this.serverConnected = isConnected;
        if(!isConnected){
            this.serversMembers.clear();
            fireContentsChanged(this, 0, getSize()-1);
        }
    }

    public void remove(String item) {
        if(serverConnected){
            serversMembers.remove(item);
        }else {
            serversList.remove(item);
        }
        fireContentsChanged(this, 0, getSize()-1);
    }

    public void add(String item) {
        if(serverConnected){
            serversMembers.add(item);
        }else {
            serversList.add(item);
        }
        fireContentsChanged(this, 0, getSize()-1);
    }

    @Override
    public int getSize() {
        if(serverConnected){
            return serversMembers.size();
        }
        return serversList.size();
    }

    public boolean contains(String item){
        if(serverConnected){
            return this.serversMembers.contains(item);
        }else {
            return this.serversList.contains(item);
        }
    }

    @Override
    public String getElementAt(int index) {
        if(serverConnected){
            return serversMembers.get(index);
        }
        return serversList.get(index);
    }
}
