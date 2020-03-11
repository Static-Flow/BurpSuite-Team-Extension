package teamextension;

import javax.swing.*;
import java.awt.*;

class ServerListModel extends DefaultListModel<Room> {

    ServerListModel() {
    }

}

class ServerListCustomCellRenderer implements ListCellRenderer<Room> {

    @Override
    public Component getListCellRendererComponent(JList<? extends Room> list, Room room, int index, boolean isSelected, boolean cellHasFocus) {
        return new JLabel(room.getRoomName());
    }
}