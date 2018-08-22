package burp;

import java.awt.*;

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