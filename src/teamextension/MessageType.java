package teamextension;

public enum MessageType {
    BURP_MESSAGE, //For sending burp request/responses
    REPEATER_MESSAGE, //For sending a burp repeater message
    INTRUDER_MESSAGE, //For sending a burp intruder message
    MUTE_MESSAGE, //For sending a mute message
    UNMUTE_MESSAGE, //For sending a unmute message
    NEW_MEMBER_MESSAGE, //For getting new members
    GET_ROOMS_MESSAGE, //For getting list of server rooms
    ADD_ROOM_MESSAGE, //For adding a new room
    JOIN_ROOM_MESSAGE, //For joining a room
    LEAVE_ROOM_MESSAGE, //For leaving a room
    SYNC_SCOPE_MESSAGE, //For syncing scope between clients
    SCAN_ISSUE_MESSAGE, //For new scan issues
    COOKIE_MESSAGE,     //For new cookies
    COMMENT_MESSAGE,    //For sending new comments
    GET_COMMENTS_MESSAGE, //For retrieving new comments
    BAD_PASSWORD_MESSAGE, //If we entered a wrong room password
    CHECK_PASSWORD_MESSAGE, //sending room password to check
    GOOD_PASSWORD_MESSAGE, //successfully auth-ed
    GET_CONFIG_MESSAGE, //For retrieving server config
    ;

}
