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


import com.github.vatbub.common.core.logging.FOKLogger;
import com.github.vatbub.common.updater.UpdateProgressDialog;

/**
 * The ui that informs the user about the update progress on the command line
 */
public class UpdateProgressUI implements UpdateProgressDialog {
    @Override
    public void preparePhaseStarted() {
        FOKLogger.info(UpdateProgressUI.class.getName(), "Preparing the update download...");
    }

    @Override
    public void downloadStarted() {
        FOKLogger.info(UpdateProgressUI.class.getName(), "Download started...");
    }

    @Override
    public void downloadProgressChanged(double kilobytesDownloaded, double totalFileSizeInKB) {
        int numberOfTicks = 100;
        double percent = kilobytesDownloaded / totalFileSizeInKB;
        int ticksToShow = (int) Math.round(percent * 100) * numberOfTicks / 100;
        int emptyTicks = numberOfTicks - ticksToShow;

        StringBuilder out = new StringBuilder("|");
        for (int i = 0; i < ticksToShow; i++) {
            out.append("=");
        }
        for (int i = 0; i < emptyTicks; i++) {
            out.append(" ");
        }
        out.append("|\r");
        System.out.print(out.toString());
    }

    @Override
    public void installStarted() {
        System.out.println();
        FOKLogger.info(UpdateProgressUI.class.getName(), "Installing the update...");
    }

    @Override
    public void launchStarted() {
        FOKLogger.info(UpdateProgressUI.class.getName(), "Launching the new CLI version...");
    }

    @Override
    public void cancelRequested() {
        FOKLogger.info(UpdateProgressUI.class.getName(), "Cancelling the update...");
    }

    @Override
    public void operationCanceled() {
        FOKLogger.info(UpdateProgressUI.class.getName(), "Update cancelled");
    }

    @Override
    public void showErrorMessage(String message) {
        FOKLogger.severe(UpdateProgressUI.class.getName(), "Could not perform update: " + message);
    }
}
