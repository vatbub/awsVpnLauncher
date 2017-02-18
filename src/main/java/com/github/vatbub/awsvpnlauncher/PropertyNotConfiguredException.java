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


import common.Common;

public class PropertyNotConfiguredException extends RuntimeException {
    public PropertyNotConfiguredException() {
        super();
    }

    public PropertyNotConfiguredException(String message) {
        super(message);
    }

    public PropertyNotConfiguredException(String message, Throwable cause) {
        super(message, cause);
    }

    public PropertyNotConfiguredException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public PropertyNotConfiguredException(Main.Property property) {
        this("Property " + property.toString() + " is not configured. Run " + Common.getPathAndNameOfCurrentJar() + " config " + property.toString() + " <value> to fix this.");
    }
}
