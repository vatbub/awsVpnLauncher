package com.github.vatbub.awsvpnlauncher.cloudflare;

/*-
 * #%L
 * AWSVpnLauncher
 * %%
 * Copyright (C) 2016 - 2018 Frederik Kammel
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


import org.json.JSONObject;

import java.net.MalformedURLException;
import java.net.URL;

public abstract class CloudflareRequest {
    public static final String baseUrlAsString = "https://api.cloudflare.com/client/v4/";
    public static final URL baseUrl;

    private CloudflareAccess cloudflareAccess;

    static {
        try {
            baseUrl = new URL(baseUrlAsString);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    public abstract JSONObject executeBasic() throws CloudflareError;

    public CloudflareAccess getCloudflareAccess() {
        return cloudflareAccess;
    }

    public void setCloudflareAccess(CloudflareAccess cloudflareAccess) {
        this.cloudflareAccess = cloudflareAccess;
    }
}
