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

public class DNSAddRecord extends CloudflareRequest {
    private String targetZoneId;
    private RecordType recordType;
    private String subdomain;
    private String publicIpAddress;

    public DNSAddRecord(CloudflareAccess cloudflareAccess, String targetZoneId, RecordType recordType, String subdomain, String publicIpAddress) {
        setCloudflareAccess(cloudflareAccess);
        setTargetZoneId(targetZoneId);
        setRecordType(recordType);
        setSubdomain(subdomain);
        setPublicIpAddress(publicIpAddress);
    }

    public String getTargetZoneId() {
        return targetZoneId;
    }

    public void setTargetZoneId(String targetZoneId) {
        this.targetZoneId = targetZoneId;
    }

    public RecordType getRecordType() {
        return recordType;
    }

    public void setRecordType(RecordType recordType) {
        this.recordType = recordType;
    }

    public String getSubdomain() {
        return subdomain;
    }

    public void setSubdomain(String subdomain) {
        this.subdomain = subdomain;
    }

    public String getPublicIpAddress() {
        return publicIpAddress;
    }

    public void setPublicIpAddress(String publicIpAddress) {
        this.publicIpAddress = publicIpAddress;
    }

    @Override
    public JSONObject executeBasic() throws CloudflareError {
        try {
            JSONObject body = new JSONObject();
            body.put("type", getRecordType());
            body.put("name", getSubdomain());
            body.put("content", getPublicIpAddress());

            HttpResponse<JsonNode> jsonResponse = Unirest.post(new URL(baseUrl, "zones/" + getTargetZoneId() + "/dns_records").toExternalForm())
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
