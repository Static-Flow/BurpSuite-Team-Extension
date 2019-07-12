package burp;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Collections;

public class ServerListModel extends DefaultListModel<String> {

    public ServerListModel(){
    }

    public ArrayList<String> getServersMembers() {
        return Collections.list(this.elements());
    }

}
