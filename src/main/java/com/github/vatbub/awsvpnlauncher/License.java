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

public enum License {
    _2Users, _5Users, _10Users, _25Users, _50Users, _100Users, _250Users, _500Users;

    public static License withMinNumberOfUsers(int minNumberOfUsers) {
        if (minNumberOfUsers <= 2) return _2Users;
        if (minNumberOfUsers <= 5) return _5Users;
        if (minNumberOfUsers <= 10) return _10Users;
        if (minNumberOfUsers <= 25) return _25Users;
        if (minNumberOfUsers <= 50) return _50Users;
        if (minNumberOfUsers <= 100) return _100Users;
        if (minNumberOfUsers <= 250) return _250Users;
        if (minNumberOfUsers <= 500) return _500Users;

        throw new IllegalArgumentException(minNumberOfUsers + " are not supported");
    }

    public int getNumberOfUsers() {
        return switch (this) {
            case _2Users -> 2;
            case _5Users -> 5;
            case _10Users -> 10;
            case _25Users -> 25;
            case _50Users -> 50;
            case _100Users -> 100;
            case _250Users -> 250;
            case _500Users -> 500;
        };
    }
}
