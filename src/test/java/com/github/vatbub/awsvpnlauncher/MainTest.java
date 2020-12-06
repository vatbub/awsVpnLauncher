package com.github.vatbub.awsvpnlauncher;

/*-
 * #%L
 * AWSVpnLauncher
 * %%
 * Copyright (C) 2016 - 2020 Frederik Kammel
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

import com.github.vatbub.common.core.Common;
import com.github.vatbub.common.core.logging.FOKLogger;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.DescribeImagesRequest;
import software.amazon.awssdk.services.ec2.model.DescribeImagesResponse;

import java.util.HashMap;
import java.util.Map;

public class MainTest {
    @BeforeClass
    public static void beforeClass() {
        Common.getInstance().setAppName("awsVpnLauncher");
    }

    @Ignore
    @Test
    public void amiIdsCorrectTest() {
        Preferences prefs = new Preferences(Main.class.getName());

        Map<Region, TestResult> results = new HashMap<>();

        for (Region region : Region.regions()) {
            String amiId;
            try {
                amiId = Main.getAmiId(region);
            } catch (RegionNotSupportedException e) {
                continue;
            }

            AwsCredentials credentials = AwsBasicCredentials.create(prefs.getPreference(Main.Property.awsKey), prefs.getPreference(Main.Property.awsSecret));
            Ec2Client client = Ec2Client.builder()
                    .region(region)
                    .credentialsProvider(StaticCredentialsProvider.create(credentials))
                    .build();

            DescribeImagesRequest request = DescribeImagesRequest.builder().imageIds(amiId).build();
            try {
                DescribeImagesResponse result = client.describeImages(request);
                Assert.assertEquals(1, result.images().size());
                results.put(region, new TestResult(result.images().size(), null));
            } catch (Exception e) {
                results.put(region, new TestResult(-1, e));
            }
        }

        long numberOfSuccessfulRegions = results.values().stream().filter(testResult -> testResult.numberOfFoundAmis == 1).count();
        FOKLogger.info(MainTest.class.getName(), "Successful regions: " + numberOfSuccessfulRegions + ", unsuccessful regions: " + (results.size() - numberOfSuccessfulRegions));
        if (numberOfSuccessfulRegions == results.size()) return;

        FOKLogger.severe(MainTest.class.getName(), "Unsuccessful regions:");
        for (Map.Entry<Region, TestResult> result : results.entrySet()) {
            if (result.getValue().getNumberOfFoundAmis() == 1) continue;

            String reason;
            if (result.getValue().getException() != null)
                reason = result.getValue().getException().getClass().getName() + ": " + result.getValue().getException().getMessage();
            else
                reason = "number of found amis was " + result.getValue().getNumberOfFoundAmis() + ", expected 1";

            FOKLogger.severe(MainTest.class.getName(), result.getKey().id() + " - Reason: " + reason);
        }
    }

    private static class TestResult {
        private int numberOfFoundAmis;
        private Throwable exception;

        public TestResult(int numberOfFoundAmis, Throwable exception) {
            this.numberOfFoundAmis = numberOfFoundAmis;
            this.exception = exception;
        }

        public int getNumberOfFoundAmis() {
            return numberOfFoundAmis;
        }

        public void setNumberOfFoundAmis(int numberOfFoundAmis) {
            this.numberOfFoundAmis = numberOfFoundAmis;
        }

        public Throwable getException() {
            return exception;
        }

        public void setException(Throwable exception) {
            this.exception = exception;
        }
    }
}
