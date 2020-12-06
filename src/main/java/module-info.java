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
module awsVpnLauncher {
    requires unirest.java;
    requires json;
    requires commandlineUserPromptProcessor;
    requires common.core;
    requires common.updater;
    requires jsch;
    requires org.jnrproject.posix;
    requires commons.io;
    requires commons.lang;
    requires java.datatransfer;
    requires java.logging;
    requires java.desktop;
    requires software.amazon.awssdk.services.ec2;
    requires software.amazon.awssdk.auth;
    requires software.amazon.awssdk.regions;
}
