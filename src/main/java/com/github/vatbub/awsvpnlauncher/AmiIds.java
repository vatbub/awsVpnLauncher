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

import org.apache.commons.lang.NotImplementedException;
import software.amazon.awssdk.regions.Region;

import static software.amazon.awssdk.regions.Region.*;

public class AmiIds {
    public static String getAmiId(Region region, License license) {
        return switch (license) {
            case _2Users -> getAmiIdFor2Users(region);
            case _5Users -> getAmiIdFor5Users(region);
            case _10Users -> getAmiIdFor10Users(region);
            case _25Users -> getAmiIdFor25Users(region);
            case _50Users -> getAmiIdFor50Users(region);
            case _100Users -> getAmiIdFor100Users(region);
            case _250Users -> getAmiIdFor250Users(region);
            case _500Users -> getAmiIdFor500Users(region);
        };
    }

    private static String getAmiIdFor2Users(Region region) {
        if (AP_SOUTH_1.equals(region)) return "ami-029cb972e1b8a4bca";
        if (EU_WEST_2.equals(region)) return "ami-056465a2a49aad6d9";
        if (EU_WEST_1.equals(region)) return "ami-0e1415fedc1664f51";
        if (AP_NORTHEAST_2.equals(region)) return "ami-0b34e8ed891410f41";
        if (AP_NORTHEAST_1.equals(region)) return "ami-04f47c2ec43830d77";
        if (SA_EAST_1.equals(region)) return "ami-04bde880fb57a5227";
        if (CA_CENTRAL_1.equals(region)) return "ami-00339d8622921f9d1";
        if (AP_SOUTHEAST_1.equals(region)) return "ami-0a8fdce33ca9cbe51";
        if (AP_SOUTHEAST_2.equals(region)) return "ami-0bb2699f6638760b5";
        if (EU_CENTRAL_1.equals(region)) return "ami-0764964fdfe99bc31";
        if (US_GOV_WEST_1.equals(region)) return "ami-0eaf3c8123abf49df";
        if (US_GOV_EAST_1.equals(region)) return "ami-055a4e2d85bd07d99";
        if (US_EAST_1.equals(region)) return "ami-037ff6453f0855c46";
        if (US_EAST_2.equals(region)) return "ami-04406fdec0f245050";
        if (US_WEST_1.equals(region)) return "ami-0ce1d8c91d5b9ee92";
        if (US_WEST_2.equals(region)) return "ami-0d10bccf2f1a6d60b";
        if (EU_WEST_3.equals(region)) return "ami-0b8d6b68595965460";
        if (EU_NORTH_1.equals(region)) return "ami-067349b5a5143523d";
        if (EU_SOUTH_1.equals(region)) return "ami-0b6d15c993d405ed4";
        if (AP_EAST_1.equals(region)) return "ami-079176f64e2f11364";
        if (ME_SOUTH_1.equals(region)) return "ami-07223e8af608e248a";
        if (AF_SOUTH_1.equals(region)) return "ami-0f63dc5cfd49df099";
        throw new RegionNotSupportedException(region);
    }

    private static String getAmiIdFor5Users(Region region) {
        if (US_EAST_1.equals(region)) return "ami-06e31403ada2e8ff4";
        if (US_EAST_2.equals(region)) return "ami-0cb106a0fd6dd45b9";
        if (US_WEST_1.equals(region)) return "ami-043db3ad3156c6358";
        if (US_WEST_2.equals(region)) return "ami-0c49d5958b5edaf7d";
        if (CA_CENTRAL_1.equals(region)) return "ami-0460cb734abe76ca4";
        if (EU_CENTRAL_1.equals(region)) return "ami-0d02fac378f05e739";
        if (EU_WEST_1.equals(region)) return "ami-05e0debeaf1bc0862";
        if (EU_WEST_2.equals(region)) return "ami-092698424b6869940";
        if (EU_WEST_3.equals(region)) return "ami-0bcb6fd01d4aecfdc";
        if (EU_NORTH_1.equals(region)) return "ami-0add15485c1d443ea";
        if (EU_SOUTH_1.equals(region)) return "ami-04be2a709e9108a14";
        if (AP_EAST_1.equals(region)) return "ami-0aa317adcda67a4cf";
        if (AP_SOUTHEAST_1.equals(region)) return "ami-0c377469e4ac94327";
        if (AP_SOUTHEAST_2.equals(region)) return "ami-069c480b31484863a";
        if (AP_NORTHEAST_2.equals(region)) return "ami-0437032918df4ad9b";
        if (AP_NORTHEAST_1.equals(region)) return "ami-0bc154627008fc910";
        if (AP_SOUTH_1.equals(region)) return "ami-0c58c245fa13e9daa";
        if (SA_EAST_1.equals(region)) return "ami-041a7024f17401729";
        if (ME_SOUTH_1.equals(region)) return "ami-0f110122bcd755eb4";
        if (AF_SOUTH_1.equals(region)) return "ami-0d158cd1284fb8b65";
        throw new RegionNotSupportedException(region);
    }

    private static String getAmiIdFor10Users(Region region) {
        throw new NotImplementedException();
    }

    private static String getAmiIdFor25Users(Region region) {
        throw new NotImplementedException();
    }

    private static String getAmiIdFor50Users(Region region) {
        throw new NotImplementedException();
    }

    private static String getAmiIdFor100Users(Region region) {
        throw new NotImplementedException();
    }

    private static String getAmiIdFor250Users(Region region) {
        throw new NotImplementedException();
    }

    private static String getAmiIdFor500Users(Region region) {
        throw new NotImplementedException();
    }
}
