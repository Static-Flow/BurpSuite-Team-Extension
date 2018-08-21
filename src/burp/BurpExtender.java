package burp;

import java.awt.*;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Map;

public class BurpExtender implements IBurpExtender, ITab
{
    private IBurpExtenderCallbacks callbacks;

    private SharedValues sharedValues;
    public static void main(String[]args) {
        StartBurp.main(args);
    }

    public void registerExtenderCallbacks(
            IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        callbacks.setExtensionName("Burp Team Collaborator");

        this.sharedValues = new SharedValues(this.callbacks);
        this.callbacks.addSuiteTab(this);

    }


    @Override
    public String getTabCaption() {
        return "Burp TC";
    }

    @Override
    public Component getUiComponent() {
        return new BurpTeamPanel(sharedValues);
    }
}

class ParameterStringBuilder {
    public static String getParamsString(Map<String, String> params)
            throws UnsupportedEncodingException {
        StringBuilder result = new StringBuilder();

        for (Map.Entry<String, String> entry : params.entrySet()) {
            result.append(URLEncoder.encode(entry.getKey(), "UTF-8"));
            result.append("=");
            result.append(URLEncoder.encode(entry.getValue(), "UTF-8"));
            result.append("&");
        }

        String resultString = result.toString();
        return resultString.length() > 0
                ? resultString.substring(0, resultString.length() - 1)
                : resultString;
    }
}