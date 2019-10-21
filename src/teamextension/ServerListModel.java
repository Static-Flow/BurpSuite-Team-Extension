package teamextension;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Collections;

class ServerListModel extends DefaultListModel<String> {

    ServerListModel() {
    }

    ArrayList<String> getServersMembers() {
        return Collections.list(this.elements());
    }

}
