package teamExtension;

import burp.IScopeChangeListener;

public class ScopeChangeListener implements IScopeChangeListener {

    private final SharedValues sharedValues;

    public ScopeChangeListener(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
    }

    @Override
    public void scopeChanged() {
        try {
            this.sharedValues.setCurrentScope(
                    this.sharedValues.getCallbacks().saveConfigAsJson("target.scope"));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
