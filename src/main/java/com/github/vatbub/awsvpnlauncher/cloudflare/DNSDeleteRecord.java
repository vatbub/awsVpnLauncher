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


import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.json.JSONObject;

import java.net.MalformedURLException;
import java.net.URL;

public class DNSDeleteRecord extends CloudflareRequest{
    private String targetZoneId;
    private String cloudflareRecordID;

    public DNSDeleteRecord(CloudflareAccess cloudflareAccess, String targetZoneId, String cloudflareRecordID) {
        setCloudflareAccess(cloudflareAccess);
        setTargetZoneId(targetZoneId);
        setCloudflareRecordID(cloudflareRecordID);
    }

    public String getTargetZoneId() {
        return targetZoneId;
    }

    public void setTargetZoneId(String targetZoneId) {
        this.targetZoneId = targetZoneId;
    }

    public String getCloudflareRecordID() {
        return cloudflareRecordID;
    }

    public void setCloudflareRecordID(String cloudflareRecordID) {
        this.cloudflareRecordID = cloudflareRecordID;
    }

    @Override
    public JSONObject executeBasic() throws  CloudflareError{
        try {
            JSONObject body = new JSONObject();

            HttpResponse<JsonNode> jsonResponse = Unirest.delete(new URL(baseUrl, "zones/" + getTargetZoneId() + "/dns_records/" + getCloudflareRecordID()).toExternalForm())
                    .header("Content-Type", "application/json")
                    .header("X-Auth-Key", getCloudflareAccess().getCloudflareAPIKey())
                    .header("X-Auth-Email", getCloudflareAccess().getCloudflareEmail())
                    .body(body)
                    .asJson();
            return jsonResponse.getBody().getObject();
        } catch (UnirestException | MalformedURLException e) {
            throw new CloudflareError(e);
        }
    }
}
