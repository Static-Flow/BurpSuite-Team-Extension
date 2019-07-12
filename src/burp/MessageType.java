package burp;

public enum MessageType {
    BURP_MESSAGE, //For sending burp request/responses
    REPEATER_MESSAGE, //For sending a burp repeater message
    INTRUDER_MESSAGE, //For sending a burp intruder message
    QUIT_MESSAGE, //For sending a goodbye message
    LOGIN_MESSAGE, //For sending a login message
    MUTE_MESSAGE, //For sending a mute message
    UNMUTE_MESSAGE, //For sending a unmute message
    NEW_MEMBER_MESSAGE //For getting new members
}
