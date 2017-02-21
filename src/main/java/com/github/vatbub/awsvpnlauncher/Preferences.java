package com.github.vatbub.awsvpnlauncher;

import common.Prefs;

/**
 * A custom implementation to preferences
 */
public class Preferences extends Prefs {
    public Preferences(String className) {
        super(className);
    }

    public String getPreference(Main.Property prefKey, String defaultValue) {
        return super.getPreference(convertPropertyToString(prefKey), defaultValue);
    }

    public void setPreference(Main.Property prefKey, String prefValue) {
        super.setPreference(convertPropertyToString(prefKey), prefValue);
    }

    private String convertPropertyToString(Main.Property property) {
        switch (property) {
            case awsKey:
            case awsSecret:
            case awsKeyPairName:
            case privateKeyFile:
                return Main.Property.awsRegion.toString() + "." + property.toString();
            default:
                return property.toString();
        }
    }
}
