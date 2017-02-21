package com.github.vatbub.awsvpnlauncher;

/*-
 * #%L
 * AWSVpnLauncher
 * %%
 * Copyright (C) 2016 - 2017 Frederik Kammel
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */


import common.Prefs;

/**
 * A custom implementation to preferences
 */
@SuppressWarnings("WeakerAccess")
public class Preferences extends Prefs {
    public Preferences(String className) {
        super(className);
    }

    public String getPreference(Main.Property prefKey) {
        String res = super.getPreference(convertPropertyToString(prefKey), "");

        if (res.equals("")) {
            throw new PropertyNotConfiguredException(prefKey);
        } else {
            return res;
        }
    }

    public void setPreference(Main.Property prefKey, String prefValue) {
        super.setPreference(convertPropertyToString(prefKey), prefValue);
    }

    private String convertPropertyToString(Main.Property property) {
        switch (property) {
            case awsKeyPairName:
            case privateKeyFile:
                return getPreference(Main.Property.awsRegion) + "." + property.toString();
            default:
                return property.toString();
        }
    }
}
