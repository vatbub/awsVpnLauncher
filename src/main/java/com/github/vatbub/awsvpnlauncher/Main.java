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


import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.*;
import com.cloudflare.api.CloudflareAccess;
import com.cloudflare.api.constants.RecordType;
import com.cloudflare.api.requests.dns.DNSAddRecord;
import com.cloudflare.api.requests.dns.DNSDeleteRecord;
import com.cloudflare.api.results.CloudflareError;
import com.github.vatbub.commandlineUserPromptProcessor.Prompt;
import com.github.vatbub.commandlineUserPromptProcessor.parsables.Parsable;
import com.github.vatbub.commandlineUserPromptProcessor.parsables.ParsableEnum;
import com.github.vatbub.commandlineUserPromptProcessor.parsables.ParseException;
import com.github.vatbub.common.core.Common;
import com.github.vatbub.common.core.Config;
import com.github.vatbub.common.core.StringCommon;
import com.github.vatbub.common.core.logging.FOKLogger;
import com.github.vatbub.common.updater.UpdateChecker;
import com.github.vatbub.common.updater.UpdateInfo;
import com.jcraft.jsch.*;
import jnr.posix.POSIX;
import jnr.posix.POSIXFactory;
import net.sf.json.JSONObject;
import org.apache.commons.io.output.NullOutputStream;
import org.apache.commons.lang.SystemUtils;

import java.awt.*;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;

public class Main {
    // internal config
    private static final String securityGroupName = "AWSVPNSecurityGroup";
    private static final String sshUsername = "openvpnas";
    private static final String adminUsername = "openvpn";
    private static final POSIX posix = POSIXFactory.getPOSIX();
    private static Instance newInstance;
    private static Session session;
    private static Preferences prefs;
    private static AmazonEC2 client;
    private static Regions awsRegion;
    private static String vpnPassword;
    private static Config mvnRepoConfig;
    private static Config projectConfig;

    public static void main(String[] args) {
        Common.setAppName("awsVpnLauncher");
        FOKLogger.enableLoggingOfUncaughtExceptions();
        prefs = new Preferences(Main.class.getName());

        // enable the shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (session != null) {
                if (session.isConnected()) {
                    session.disconnect();
                }
            }
        }));

        UpdateChecker.completeUpdate(args, (oldVersion, oldFile) -> {
            if (oldVersion != null) {
                FOKLogger.info(Main.class.getName(), "Successfully upgraded " + Common.getAppName() + " from v" + oldVersion.toString() + " to v" + Common.getAppVersion());
            }
        });
        List<String> argsAsList = new ArrayList<>(Arrays.asList(args));

        for (String arg : args) {
            if (arg.toLowerCase().matches("mockappversion=.*")) {
                // Set the mock version
                String version = arg.substring(arg.toLowerCase().indexOf('=') + 1);
                Common.setMockAppVersion(version);
                argsAsList.remove(arg);
            } else if (arg.toLowerCase().matches("mockbuildnumber=.*")) {
                // Set the mock build number
                String buildnumber = arg.substring(arg.toLowerCase().indexOf('=') + 1);
                Common.setMockBuildNumber(buildnumber);
                argsAsList.remove(arg);
            } else if (arg.toLowerCase().matches("mockpackaging=.*")) {
                // Set the mock packaging
                String packaging = arg.substring(arg.toLowerCase().indexOf('=') + 1);
                Common.setMockPackaging(packaging);
                argsAsList.remove(arg);
            }
        }

        args = argsAsList.toArray(new String[0]);

        try {
            mvnRepoConfig = new Config(new URL("https://www.dropbox.com/s/vnhs4nax2lczccf/mavenRepoConfig.properties?dl=1"), Main.class.getResource("mvnRepoFallbackConfig.properties"), "mvnRepoCachedConfig");
            projectConfig = new Config(new URL("https://www.dropbox.com/s/d36hwrrufoxfmm7/projectConfig.properties?dl=1"), Main.class.getResource("projectFallbackConfig.properties"), "projectCachedConfig");
        } catch (IOException e) {
            FOKLogger.log(Main.class.getName(), Level.SEVERE, "Could not load the remote config", e);
        }

        try {
            installUpdates(args);
        } catch (Exception e) {
            FOKLogger.log(Main.class.getName(), Level.SEVERE, "Could not install updates", e);
        }

        if (args.length == 0) {
            // not enough arguments
            printHelpMessage();
            throw new NotEnoughArgumentsException();
        }

        switch (args[0].toLowerCase()) {
            case "setup":
                setup();
                break;
            case "launch":
                initAWSConnection();
                launch();
                break;
            case "terminate":
                initAWSConnection();
                terminate();
                break;
            case "config":
                // require a second arg
                if (args.length == 2) {
                    // not enough arguments
                    printHelpMessage();
                    throw new NotEnoughArgumentsException();
                }

                config(Property.valueOf(args[1]), args[2]);
                break;
            case "getconfig":
                // require a second arg
                if (args.length == 1) {
                    // not enough arguments
                    printHelpMessage();
                    throw new NotEnoughArgumentsException();
                }

                getConfig(Property.valueOf(args[1]));
                break;
            case "printconfig":
                printConfig();
                break;
            case "deleteconfig":
                // require a second arg
                if (args.length == 1) {
                    // not enough arguments
                    printHelpMessage();
                    throw new NotEnoughArgumentsException();
                }

                deleteConfig(Property.valueOf(args[1]));
                break;
            case "ssh":
                String sshInstanceId;
                if (args.length == 2) {
                    // a instanceID is specified
                    sshInstanceId = args[1];
                } else {
                    String instanceIdsPrefValue = prefs.getPreference("instanceIDs", "");
                    if (instanceIdsPrefValue.equals("")) {
                        throw new NotEnoughArgumentsException("No instanceId was specified to connect to and no instanceId was saved in the preference file. Please either start another instance using the launch command or specify the instance id of the instance to connect to as a additional parameter.");
                    }

                    List<String> instanceIds = Arrays.asList(instanceIdsPrefValue.split(";"));
                    if (instanceIds.size() == 1) {
                        // exactly one instance found
                        sshInstanceId = instanceIds.get(0);
                    } else {
                        FOKLogger.severe(Main.class.getName(), "Multiple instance ids found:");

                        for (String instanceId : instanceIds) {
                            FOKLogger.severe(Main.class.getName(), instanceId);
                        }
                        throw new NotEnoughArgumentsException("Multiple instance ids were found in the preference file. Please specify the instance id of the instance to connect to as a additional parameter.");
                    }
                }

                initAWSConnection();
                ssh(sshInstanceId);
                break;
            default:
                printHelpMessage();
        }
    }

    private static void initAWSConnection() {
        AWSCredentials credentials = new BasicAWSCredentials(prefs.getPreference(Property.awsKey), prefs.getPreference(Property.awsSecret));
        awsRegion = Regions.valueOf(prefs.getPreference(Property.awsRegion));
        client = AmazonEC2ClientBuilder.standard().withCredentials(new AWSStaticCredentialsProvider(credentials)).withRegion(awsRegion).build();
    }

    /**
     * Returns the name of the ami to use
     *
     * @param region The region where the AWS EC2 instance is launched
     * @return The name of the ami to use
     */
    private static String getAmiId(Regions region) {
        /*
        Asia Pacific (Mumbai) 	ami-cdd4aaa2
        EU (London) 	ami-17c5d373
        EU (Ireland) 	ami-238b6a5a
        Asia Pacific (Seoul) 	ami-c98c52a7
        Asia Pacific (Tokyo) 	ami-dee1fdb9
        South America (Sao Paulo) 	ami-930673ff
        Canada (Central) 	ami-c6813ea2
        Asia Pacific (Singapore) 	ami-81d75de2
        Asia Pacific (Sydney) 	ami-3cd6c45f
        EU (Frankfurt) 	ami-17862678
        US East (N. Virginia) 	ami-f6eed4e0
        US East (Ohio) 	ami-6d163708
        US West (N. California) 	ami-091f3069
        US West (Oregon) 	ami-e346559a
         */

        switch (region) {
            case AP_SOUTH_1:
                return "ami-cdd4aaa2";
            case EU_WEST_2:
                return "ami-17c5d373";
            case EU_WEST_1:
                return "ami-238b6a5a";
            case AP_NORTHEAST_2:
                return "ami-c98c52a7";
            case AP_NORTHEAST_1:
                return "ami-dee1fdb9";
            case SA_EAST_1:
                return "ami-930673ff";
            case CA_CENTRAL_1:
                return "ami-c6813ea2";
            case AP_SOUTHEAST_1:
                return "ami-81d75de2";
            case AP_SOUTHEAST_2:
                return "ami-3cd6c45f";
            case EU_CENTRAL_1:
                return "ami-17862678";
            case US_EAST_1:
                return "ami-f6eed4e0";
            case US_EAST_2:
                return "ami-6d163708";
            case US_WEST_1:
                return "ami-091f3069";
            case US_WEST_2:
                return "ami-e346559a";
            default:
                throw new RegionNotSupportedException(region);
        }
    }

    /**
     * Launches a new VPN server on AWS EC2 if everything is configured
     *
     * @see PropertyNotConfiguredException
     * @see #terminate()
     */
    private static void launch() {
        File privateKey = new File(prefs.getPreference(Property.privateKeyFile));
        vpnPassword = prefs.getPreference(Property.openvpnPassword);

        if (!privateKey.exists() && !privateKey.isFile()) {
            throw new IllegalArgumentException("The file specified as " + Property.privateKeyFile.toString() + " does not exist or is not a file.");
        }

        FOKLogger.info(Main.class.getName(), "Preparing...");

        try {
            // Check if our security group exists already
            FOKLogger.info(Main.class.getName(), "Checking for the required security group...");
            DescribeSecurityGroupsRequest describeSecurityGroupsRequest = new DescribeSecurityGroupsRequest().withGroupNames(securityGroupName);

            List<String> securityGroups = new ArrayList<>();
            boolean created = false; // will become true if the security group had to be created to avoid duplicate logs
            String securityGroupId;
            try {
                DescribeSecurityGroupsResult describeSecurityGroupsResult = client.describeSecurityGroups(describeSecurityGroupsRequest);
                securityGroupId = describeSecurityGroupsResult.getSecurityGroups().get(0).getGroupId();
            } catch (AmazonEC2Exception e) {
                // Security group does not exist, create the security group
                created = true;
                FOKLogger.info(Main.class.getName(), "Creating the required security group...");
                CreateSecurityGroupRequest createSecurityGroupRequest = new CreateSecurityGroupRequest()
                        .withGroupName(securityGroupName)
                        .withDescription("This security group was automatically created to run a OpenVPN Access Server.");
                CreateSecurityGroupResult createSecurityGroupResult = client.createSecurityGroup(createSecurityGroupRequest);

                securityGroupId = createSecurityGroupResult.getGroupId();

                IpRange ipRange = new IpRange().withCidrIp("0.0.0.0/0");
                IpPermission sshPermission1 = new IpPermission().withIpv4Ranges(ipRange)
                        .withIpProtocol("tcp")
                        .withFromPort(22)
                        .withToPort(22);
                IpPermission sshPermission2 = new IpPermission().withIpv4Ranges(ipRange)
                        .withIpProtocol("tcp")
                        .withFromPort(943)
                        .withToPort(943);
                IpPermission httpsPermission1 = new IpPermission().withIpv4Ranges(ipRange)
                        .withIpProtocol("tcp")
                        .withFromPort(443)
                        .withToPort(443);
                IpPermission httpsPermission2 = new IpPermission().withIpv4Ranges(ipRange)
                        .withIpProtocol("udp")
                        .withFromPort(1194)
                        .withToPort(1194);

                AuthorizeSecurityGroupIngressRequest authorizeSecurityGroupIngressRequest =
                        new AuthorizeSecurityGroupIngressRequest().withGroupName(securityGroupName)
                                .withIpPermissions(sshPermission1)
                                .withIpPermissions(sshPermission2)
                                .withIpPermissions(httpsPermission1)
                                .withIpPermissions(httpsPermission2);

                // retry while the security group is not yet ready
                int retries = 0;
                long lastPollTime = System.currentTimeMillis();
                boolean requestIsFailing = true;

                do {
                    // we're waiting

                    if (System.currentTimeMillis() - lastPollTime >= Math.pow(2, retries) * 100) {
                        retries = retries + 1;
                        lastPollTime = System.currentTimeMillis();
                        try {
                            client.authorizeSecurityGroupIngress(authorizeSecurityGroupIngressRequest);
                            // no exception => we made it
                            requestIsFailing = false;
                        } catch (AmazonEC2Exception e2) {
                            FOKLogger.info(Main.class.getName(), "Still waiting for the security group to be created, api error message is currently: " + e2.getMessage());
                            requestIsFailing = true;
                        }
                    }
                } while (requestIsFailing);
                FOKLogger.info(Main.class.getName(), "The required security group has been successfully created!");
            }

            if (!created) {
                FOKLogger.info(Main.class.getName(), "The required security group already exists, we can continue");
            }
            securityGroups.add(securityGroupId);

            securityGroups.add(securityGroupId);

            FOKLogger.info(Main.class.getName(), "Creating the RunInstanceRequest...");
            RunInstancesRequest request = new RunInstancesRequest(getAmiId(awsRegion), 1, 1);
            request.setInstanceType(InstanceType.T2Micro);
            request.setKeyName(prefs.getPreference(Property.awsKeyPairName));
            request.setSecurityGroupIds(securityGroups);

            FOKLogger.info(Main.class.getName(), "Starting the EC2 instance...");
            RunInstancesResult result = client.runInstances(request);
            List<Instance> instances = result.getReservation().getInstances();

            // SSH config
            FOKLogger.info(Main.class.getName(), "Configuring SSH...");
            Properties sshConfig = new Properties();
            sshConfig.put("StrictHostKeyChecking", "no");
            JSch jsch = new JSch();
            jsch.addIdentity(privateKey.getAbsolutePath());
            int retries = 0;

            for (Instance instance : instances) {
                // write the instance id to a properties file to be able to terminate it later on again
                prefs.reload();
                if (prefs.getPreference("instanceIDs", "").equals("")) {
                    prefs.setPreference("instanceIDs", instance.getInstanceId());
                } else {
                    prefs.setPreference("instanceIDs", prefs.getPreference("instanceIDs", "") + ";" + instance.getInstanceId());
                }

                // Connect to the instance using ssh
                FOKLogger.info(Main.class.getName(), "Waiting for the instance to boot...");

                long lastPrintTime = System.currentTimeMillis();
                DescribeInstancesRequest describeInstancesRequest = new DescribeInstancesRequest();
                List<String> instanceId = new ArrayList<>(1);
                instanceId.add(instance.getInstanceId());
                describeInstancesRequest.setInstanceIds(instanceId);
                DescribeInstancesResult describeInstancesResult;
                newInstance = instance;

                do {
                    // we're waiting

                    if (System.currentTimeMillis() - lastPrintTime >= Math.pow(2, retries) * 100) {
                        retries = retries + 1;
                        describeInstancesResult = client.describeInstances(describeInstancesRequest);
                        newInstance = describeInstancesResult.getReservations().get(0).getInstances().get(0);
                        lastPrintTime = System.currentTimeMillis();
                        if (newInstance.getState().getCode() != 16) {
                            FOKLogger.info(Main.class.getName(), "Still waiting for the instance to boot, current instance state is " + newInstance.getState().getName());
                        }
                    }
                } while (newInstance.getState().getCode() != 16);

                FOKLogger.info(Main.class.getName(), "Instance is " + newInstance.getState().getName());

                // generate the ssh ip of the instance
                String sshIp = newInstance.getPublicDnsName();

                FOKLogger.info(Main.class.getName(), "The instance id is " + newInstance.getInstanceId());
                FOKLogger.info(Main.class.getName(), "The instance ip is " + newInstance.getPublicIpAddress());
                FOKLogger.info(Main.class.getName(), "Connecting using ssh to " + sshUsername + "@" + sshIp);
                FOKLogger.info(Main.class.getName(), "The instance will need some time to configure ssh on its end so some connection timeouts are normal");
                boolean retry;
                session = jsch.getSession(sshUsername, sshIp, 22);
                session.setConfig(sshConfig);
                do {
                    try {
                        session.connect();
                        retry = false;
                    } catch (Exception e) {
                        FOKLogger.info(Main.class.getName(), e.getClass().getName() + ": " + e.getMessage() + ", retrying, Press Ctrl+C to cancel");
                        retry = true;
                    }
                } while (retry);

                FOKLogger.info(Main.class.getName(), "----------------------------------------------------------------------");
                FOKLogger.info(Main.class.getName(), "The following is the out- and input of the ssh session.");
                FOKLogger.info(Main.class.getName(), "Please note that out- and input may appear out of sync.");
                FOKLogger.info(Main.class.getName(), "----------------------------------------------------------------------");

                PipedInputStream sshIn = new PipedInputStream();
                PipedOutputStream sshIn2 = new PipedOutputStream(sshIn);
                PrintStream sshInCommandStream = new PrintStream(sshIn2);
                Channel channel = session.openChannel("shell");
                channel.setInputStream(sshIn);
                channel.setOutputStream(new MyPrintStream());
                channel.connect();

                sshInCommandStream.print("yes\n");
                sshInCommandStream.print("yes\n");
                sshInCommandStream.print("1\n");
                sshInCommandStream.print("\n");
                sshInCommandStream.print("\n");
                sshInCommandStream.print("yes\n");
                sshInCommandStream.print("yes\n");
                sshInCommandStream.print("\n");
                sshInCommandStream.print("\n");
                sshInCommandStream.print("\n");
                sshInCommandStream.print("\n");
                sshInCommandStream.print("echo \"" + adminUsername + ":" + vpnPassword + "\" | sudo chpasswd\n");
                sshInCommandStream.print("exit\n");

                NullOutputStream nullOutputStream = new NullOutputStream();
                Thread watchForSSHDisconnectThread = new Thread(() -> {
                    while (channel.isConnected()) {
                        nullOutputStream.write(0);
                    }
                    // disconnected
                    cont();
                });
                watchForSSHDisconnectThread.setName("watchForSSHDisconnectThread");
                watchForSSHDisconnectThread.start();
            }
        } catch (JSchException | IOException e) {
            e.printStackTrace();
            if (session != null) {
                session.disconnect();
            }
            System.exit(1);
        }
    }

    /**
     * Finalizes the launch of a AWS EC2 instance after the server configuration terminated successfully
     */
    private static void cont() {
        try {
            System.out.println();
            System.out.println();
            FOKLogger.info(Main.class.getName(), "----------------------------------------------------------------------");
            FOKLogger.info(Main.class.getName(), "Disconnecting the SSH-session...");
            FOKLogger.info(Main.class.getName(), "----------------------------------------------------------------------");

            String finalIP = newInstance.getPublicIpAddress();

            if (!prefs.getPreference("cloudflareRecordID", "0").equals("0")) {
                FOKLogger.severe(Main.class.getName(), "Cannot create a new DNS record as another instance is already using it.");
            } else {
                try {
                    String cloudflareAPIKey = prefs.getPreference(Property.cloudflareAPIKey);
                    String cloudflareEmail = prefs.getPreference(Property.cloudflareEmail);
                    String targetDomain = prefs.getPreference(Property.cloudflareTargetDomain);
                    String subdomain = prefs.getPreference(Property.cloudflareSubdomain);

                    CloudflareAccess cloudflareAccess = new CloudflareAccess(cloudflareEmail, cloudflareAPIKey);
                    DNSAddRecord cloudflareAddDNSRequest = new DNSAddRecord(cloudflareAccess, targetDomain, RecordType.IPV4Address, subdomain, newInstance.getPublicIpAddress());

                    FOKLogger.info(Main.class.getName(), "Creating the DNS record on cloudflare...");
                    JSONObject cloudflareResult = cloudflareAddDNSRequest.executeBasic();

                    if (cloudflareResult == null) {
                        FOKLogger.severe(Main.class.getName(), "Something went wrong while creating the DNS record for the vpn server on Cloudflare.");
                    } else {
                        // Get the record id
                        String cloudflareRecID = cloudflareResult.getJSONObject("rec").getJSONObject("obj").getString("rec_id");
                        prefs.setPreference("cloudflareRecordID", cloudflareRecID);
                        finalIP = subdomain + "." + targetDomain;
                        FOKLogger.info(Main.class.getName(), "The DNS record for the VPN Server was successfully created");
                        FOKLogger.fine(Main.class.getName(), "Cloudflare request result:");
                        FOKLogger.fine(Main.class.getName(), cloudflareResult.toString());
                    }

                } catch (PropertyNotConfiguredException e) {
                    FOKLogger.info(Main.class.getName(), "Cloudflare config is not defined, not sending the ip to cloudflare");
                } catch (CloudflareError e) {
                    FOKLogger.log(Main.class.getName(), Level.SEVERE, "Could not create the DNS record on cloudflare", e);
                }
            }

            List<String> endMessage = new ArrayList<>();
            endMessage.add("You can now connect to the VPN server using the following ip address:");
            endMessage.add(finalIP);
            endMessage.add("username: " + adminUsername);
            endMessage.add("password: " + vpnPassword);
            endMessage.add("Go to the following url to get the VPN client:");
            endMessage.add("https://" + finalIP + ":943" + "/");
            endMessage.add("Go to the following url to access the admin page:");
            endMessage.add("https://" + finalIP + ":943" + "/admin");

            List<String> formattedMessage = StringCommon.formatMessage(endMessage);
            for (String line : formattedMessage) {
                FOKLogger.info(Main.class.getName(), line);
            }
            session.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
            session.disconnect();
            System.exit(1);
        }
    }

    /**
     * Terminates all AWS instances that were started using this app
     *
     * @see #launch()
     */
    private static void terminate() {
        String instanceIdsPrefValue = prefs.getPreference("instanceIDs", "");
        if (instanceIdsPrefValue.equals("")) {
            throw new IllegalStateException("No instance was started with this script so no instance can be terminated. Launch a new instance using the launch command prior to terminate it.");
        }

        FOKLogger.info(Main.class.getName(), "Sending the termination request to AWS EC2...");
        List<String> instanceIds = Arrays.asList(instanceIdsPrefValue.split(";"));
        for (String instanceId : instanceIds) {
            try {
                List<String> instanceIdCopy = new ArrayList<>();
                instanceIdCopy.add(instanceId);
                TerminateInstancesRequest request = new TerminateInstancesRequest(instanceIdCopy);
                TerminateInstancesResult result = client.terminateInstances(request);

                for (InstanceStateChange item : result.getTerminatingInstances()) {
                    FOKLogger.info(Main.class.getName(), "Terminated instance: " + item.getInstanceId() + ", instance state changed from " + item.getPreviousState() + " to " + item.getCurrentState());
                }
            } catch (AmazonEC2Exception e) {
                FOKLogger.severe(Main.class.getName(), "Could not terminate instance " + instanceId + ": " + e.getMessage());
            }
        }

        try {
            String cloudflareAPIKey = prefs.getPreference(Property.cloudflareAPIKey);
            String cloudflareEmail = prefs.getPreference(Property.cloudflareEmail);
            String targetDomain = prefs.getPreference(Property.cloudflareTargetDomain);
            int cloudflareRecordID = Integer.parseInt(prefs.getPreference("cloudflareRecordID", "0"));

            CloudflareAccess cloudflareAccess = new CloudflareAccess(cloudflareEmail, cloudflareAPIKey);
            DNSDeleteRecord cloudFlareDeleteDNSRecordRequest = new DNSDeleteRecord(cloudflareAccess, targetDomain, cloudflareRecordID);

            FOKLogger.info(Main.class.getName(), "Deleting the DNS record on cloudflare...");
            JSONObject cloudflareResult = cloudFlareDeleteDNSRecordRequest.executeBasic();

            if (cloudflareResult == null) {
                FOKLogger.severe(Main.class.getName(), "Something went wrong while deleting the DNS record for the vpn server on Cloudflare.");
            } else {
                prefs.setPreference("cloudflareRecordID", "0");
                FOKLogger.info(Main.class.getName(), "The DNS record for the VPN Server was successfully deleted");
                FOKLogger.fine(Main.class.getName(), "Cloudflare request result:");
                FOKLogger.fine(Main.class.getName(), cloudflareResult.toString());
            }
        } catch (PropertyNotConfiguredException e) {
            FOKLogger.info(Main.class.getName(), "Cloudflare config is not defined, not sending the ip to cloudflare");
        } catch (CloudflareError e) {
            FOKLogger.log(Main.class.getName(), Level.SEVERE, "Something went wrong while deleting the DNS record for the vpn server on Cloudflare.", e);
        }

        // Delete the config value
        prefs.setPreference("instanceIDs", "");
    }

    /**
     * Prints the help message to the console
     */
    private static void printHelpMessage() {
        FOKLogger.info(Main.class.getName(), Common.getAppName() + ", v" + Common.getAppVersion());
        FOKLogger.info(Main.class.getName(), "Usage:");
        FOKLogger.info(Main.class.getName(), "java -jar " + Common.getPathAndNameOfCurrentJar() + " <command> <options>");
        FOKLogger.info(Main.class.getName(), "");
        FOKLogger.info(Main.class.getName(), "Valid commands are:");
        FOKLogger.info(Main.class.getName(), "\tlaunch:\tlaunches a new VPN server on AWS EC2.");
        FOKLogger.info(Main.class.getName(), "\tterminate:\tTerminates a previously launched VPN server on AWS EC2.");
        FOKLogger.info(Main.class.getName(), "\tconfig <propertyName> <propertyValue>: Sets the value of a config property.");
        FOKLogger.info(Main.class.getName(), "\t\toptions:");
        FOKLogger.info(Main.class.getName(), "\t\t\tpropertyName:\tThe name of the property to be modified");
        FOKLogger.info(Main.class.getName(), "\t\t\tpropertyValue:\tThe new value of the specified property");
        FOKLogger.info(Main.class.getName(), "\tgetConfig <propertyName>: Prints the current value of the specified property.");
        FOKLogger.info(Main.class.getName(), "\t\toptions:");
        FOKLogger.info(Main.class.getName(), "\t\t\tpropertyName:\tThe name of the property to be printed");
        FOKLogger.info(Main.class.getName(), "\tprintConfig: Prints the value of all currently configured parameters for the current awsRegion.");
        FOKLogger.info(Main.class.getName(), "\tdeleteConfig <propertyName>: Deletes the value of the specified property.");
        FOKLogger.info(Main.class.getName(), "\t\toptions:");
        FOKLogger.info(Main.class.getName(), "\t\t\tpropertyName:\tThe name of the property to be deleted");
        FOKLogger.info(Main.class.getName(), "\tssh <instanceID>: Connects to the specified instance using ssh.");
        FOKLogger.info(Main.class.getName(), "\t\toptions:");
        FOKLogger.info(Main.class.getName(), "\t\t\tinstanceID:\tOptional. The instance of the id to connect to. If not specified, the script will try to connect to the previously launched instance.");
        FOKLogger.info(Main.class.getName(), "");
        FOKLogger.info(Main.class.getName(), "Properties to be configured for a successful launch:");
        FOKLogger.info(Main.class.getName(), "\tawsKey: The key to use to authenticate on aws. The key must have full access to EC2. Your aws credentials are stored in plain text on your hard drive.");
        FOKLogger.info(Main.class.getName(), "\tawsSecret: The secret string that corresponds to the awsKey. Your aws credentials are stored in plain text on your hard drive.");
        FOKLogger.info(Main.class.getName(), "\tawsKeyPairName: The name of the Public/Private keypair to be used to authenticate on the newly created EC2 instances as shown in the EC2 management console");
        FOKLogger.info(Main.class.getName(), "\tawsRegion: The region where you want your VPN to be located. Can be either: (Only specify the key of the region like US_EAST_1, the city name is just for your orientation");
        FOKLogger.info(Main.class.getName(), "\t\tUS_EAST_1 (Virginia)");
        FOKLogger.info(Main.class.getName(), "\t\tUS_EAST_2 (Ohio)");
        FOKLogger.info(Main.class.getName(), "\t\tUS_WEST_1 (Northern California)");
        FOKLogger.info(Main.class.getName(), "\t\tUS_WEST_2 (Oregon)");
        FOKLogger.info(Main.class.getName(), "\t\tCA_CENTRAL_1 (Canada)");
        FOKLogger.info(Main.class.getName(), "\t\tEU_WEST_1 (Ireland)");
        FOKLogger.info(Main.class.getName(), "\t\tEU_WEST_2 (London)");
        FOKLogger.info(Main.class.getName(), "\t\tEU_CENTRAL_1 (Frankfurt)");
        FOKLogger.info(Main.class.getName(), "\t\tAP_SOUTH_1 (Mumbai)");
        FOKLogger.info(Main.class.getName(), "\t\tAP_SOUTHEAST_1 (Singapore)");
        FOKLogger.info(Main.class.getName(), "\t\tAP_SOUTHEAST_2 (Sydney)");
        FOKLogger.info(Main.class.getName(), "\t\tAP_NORTHEAST_1 (Tokyo)");
        FOKLogger.info(Main.class.getName(), "\t\tAP_NORTHEAST_2 (Seoul)");
        FOKLogger.info(Main.class.getName(), "\t\tSA_EAST_1 (Sao Paulo)");
        FOKLogger.info(Main.class.getName(), "\tprivateKeyFile: The fully qualified path to the private key file to authenticate on the EC2 instance using ssh. Example: C:\\Users\\Frederik\\.ssh\\frankfurtKey.pem");
        FOKLogger.info(Main.class.getName(), "\topenvpnPassword: The password to be set on the vpn server to access vpn and the admin area. Unfortunately, we cannot change the default username, but you can connect to the server yourself after its initial setup using ssh and add another user yourself.");
        FOKLogger.info(Main.class.getName(), "");
        FOKLogger.info(Main.class.getName(), "The properties awsKeyPairName and privateKeyFile are saved on a per region basis, that means that you can configure several regions and switch the region just by modifying the awsRegion property.");
        FOKLogger.info(Main.class.getName(), "");
        FOKLogger.info(Main.class.getName(), "Examples:");
        FOKLogger.info(Main.class.getName(), "java -jar " + Common.getPathAndNameOfCurrentJar() + " launch");
        FOKLogger.info(Main.class.getName(), "java -jar " + Common.getPathAndNameOfCurrentJar() + " terminate");
        FOKLogger.info(Main.class.getName(), "java -jar " + Common.getPathAndNameOfCurrentJar() + " config awsKey <yourAwsKeyHere>");
        FOKLogger.info(Main.class.getName(), "java -jar " + Common.getPathAndNameOfCurrentJar() + " getConfig awsKey");
    }

    /**
     * Sets the value of the specified {@link Property}
     *
     * @param property The {@link Property} to be modified
     * @param value    The value to set
     * @see #getConfig(Property)
     * @see #deleteConfig(Property)
     * @see #printConfig()
     */
    private static void config(Property property, String value) {
        prefs.setPreference(property, value);
        FOKLogger.info(Main.class.getName(), "Set the preference " + property.toString() + " to " + value);
    }

    /**
     * Prints the value of the specified config-{@link Property} to the console
     *
     * @param property The {@link Property} whose value shall be printed
     */
    private static void getConfig(Property property) {
        FOKLogger.info(Main.class.getName(), "Value of property " + property.toString() + " is: " + prefs.getPreference(property));
    }

    /**
     * Deletes the specified config parameter from the current config
     *
     * @param property The {@link Property} to delete
     */
    private static void deleteConfig(Property property) {
        String previousValue = prefs.getPreference(property);
        prefs.setPreference(property, "");
        FOKLogger.info(Main.class.getName(), "Deleted the value for the property " + property.toString() + ", previous value was: " + previousValue);
    }

    /**
     * Prints the entire current config to the console
     */
    private static void printConfig() {
        FOKLogger.info(Main.class.getName(), "The current config is:");
        FOKLogger.info(Main.class.getName(), "Property\t\tValue");
        for (Property property : Property.values()) {
            try {
                FOKLogger.info(Main.class.getName(), property.toString() + "\t\t" + prefs.getPreference(property));
            } catch (PropertyNotConfiguredException e) {
                FOKLogger.log(Main.class.getName(), Level.SEVERE, "Property " + property.toString() + " is not configured", e);
            }
        }
    }

    /**
     * Connects to the specified instance using ssh. Output will be sent to System.out, input will be taken from System.in
     *
     * @param instanceID The id of the instance to connect to
     */
    private static void ssh(String instanceID) {
        try {
            File privateKey = new File(prefs.getPreference(Property.privateKeyFile));
            DescribeInstancesRequest describeInstancesRequest = new DescribeInstancesRequest();
            List<String> instanceId = new ArrayList<>(1);
            instanceId.add(instanceID);
            describeInstancesRequest.setInstanceIds(instanceId);
            DescribeInstancesResult describeInstancesResult = client.describeInstances(describeInstancesRequest);
            Instance instance = describeInstancesResult.getReservations().get(0).getInstances().get(0);

            String sshIp = instance.getPublicDnsName();

            // SSH config
            FOKLogger.info(Main.class.getName(), "Configuring SSH...");
            Properties sshConfig = new Properties();
            sshConfig.put("StrictHostKeyChecking", "no");
            JSch jsch = new JSch();
            jsch.addIdentity(privateKey.getAbsolutePath());

            FOKLogger.info(Main.class.getName(), "Connecting using ssh to " + sshUsername + "@" + sshIp);
            session = jsch.getSession(sshUsername, sshIp, 22);

            session.setConfig(sshConfig);
            try {
                session.connect();
            } catch (Exception e) {
                FOKLogger.log(Main.class.getName(), Level.SEVERE, "Could not connect to the instance due to an exception", e);
            }

            // Connected
            FOKLogger.info(Main.class.getName(), "Connection established, connected to " + sshUsername + "@" + sshIp);

            Channel channel = session.openChannel("shell");

            if (posix.isatty(FileDescriptor.out)) {
                FOKLogger.info(Main.class.getName(), "Connected to a tty, disabling colors...");
                // Disable colors
                ((ChannelShell) channel).setPtyType("vt102");
            }

            channel.setInputStream(copyAndFilterInputStream());
            channel.setOutputStream(new MyPrintStream());
            channel.connect();

            NullOutputStream nullOutputStream = new NullOutputStream();
            Thread watchForSSHDisconnectThread = new Thread(() -> {
                while (channel.isConnected()) {
                    nullOutputStream.write(0);
                }
                // disconnected
                System.exit(0);
            });
            watchForSSHDisconnectThread.setName("watchForSSHDisconnectThread");
            watchForSSHDisconnectThread.start();

        } catch (JSchException | IOException e) {
            FOKLogger.log(Main.class.getName(), Level.SEVERE, "An error occurred", e);
        }
    }

    /**
     * Copies {@code System.in} to new {@code InputStream}. Filters {@code CrLf}s ({@code \r\n} in Java) out and replaces them with a single {@code \n} ({@code \n} in Java)
     *
     * @return The {@code InputStream} to which the filtered contents are forwarded to.
     * @throws IOException If {@code System.in} cannot be read for any reason
     */
    private static InputStream copyAndFilterInputStream() throws IOException {
        PipedOutputStream forwardTo = new PipedOutputStream();
        PipedInputStream res = new PipedInputStream(forwardTo);
        Thread pipeThread = new Thread(() -> {
            while (true) {
                try {
                    char ch = (char) System.in.read();
                    if (ch != '\r' && !SystemUtils.IS_OS_MAC) {
                        forwardTo.write((int) ch);
                    }
                } catch (IOException e) {
                    FOKLogger.log(Main.class.getName(), Level.SEVERE, "Stopped forwarding System in due to an exception", e);
                    break;
                }
            }
        });
        pipeThread.setName("pipeThread");
        pipeThread.start();

        return res;
    }

    private static void installUpdates(String[] startupArgs) throws IOException {
        UpdateInfo updateInfo = UpdateChecker.isUpdateAvailableCompareAppVersion(new URL(mvnRepoConfig.getValue("repoBaseURL")), projectConfig.getValue("groupId"), projectConfig.getValue("artifactId"), "jar-with-dependencies", "jar");
        if (updateInfo.showAlert) {
            UpdateChecker.downloadAndInstallUpdate(updateInfo, new UpdateProgressUI(), true, true, true, startupArgs);
        }
    }

    private static void setup() {
        FOKLogger.info(Main.class.getName(), "Welcome to the awsVPNLauncher v" + Common.getAppVersion());
        FOKLogger.info(Main.class.getName(), "You will now be guided through the setup process.");
        FOKLogger.info(Main.class.getName(), "You will have to do this only once.");
        FOKLogger.info(Main.class.getName(), "If you already did the setup once, setup will override previous values.");

        FOKLogger.info(Main.class.getName(), "--------------------------------------------------------------------------");
        FOKLogger.info(Main.class.getName(), "Amazon AWS Account");
        FOKLogger.info(Main.class.getName(), "--------------------------------------------------------------------------");
        FOKLogger.info(Main.class.getName(), "Once you hit enter, your browser will be opened and you will be guided to");
        FOKLogger.info(Main.class.getName(), "the Amazon AWS login page.");
        FOKLogger.info(Main.class.getName(), "If you already have an Amazon Account, you can use that, if not, please create a new account.");
        FOKLogger.info(Main.class.getName(), "Once you logged in, please return to this window to read the new instructions.");

        FOKLogger.info(Main.class.getName(), "Press enter to continue...");
        try {
            //noinspection unused
            int readResult = System.in.read();
        } catch (IOException e) {
            FOKLogger.log(Main.class.getName(), Level.SEVERE, "Could not read from System.in, resuming setup...", e);
        }

        boolean cont = false;
        while (!cont) {
            try {
                Desktop.getDesktop().browse(new URI(projectConfig.getValue("awsCreateIAMUserURL")));
            } catch (IOException | URISyntaxException e) {
                FOKLogger.log(Main.class.getName(), Level.SEVERE, "Could not open the login page", e);
                cont = true;
            }

            try {
                Parsable result = new Prompt("Reload the login page or continue?", new ParsableEnum<>(ReloadContinue.class, ReloadContinue.Reload)).doPrompt();
                if (result.toValue() == ReloadContinue.Continue) {
                    cont = true;
                }
            } catch (ParseException e) {
                cont = false;
                if (e.getMessage() != null) {
                    FOKLogger.severe(Main.class.getName(), "Unable to parse the input: " + e.getMessage());
                } else {
                    FOKLogger.severe(Main.class.getName(), "Unable to parse the input");
                }
            }
        }
    }

    /**
     * Possible config properties
     */
    public enum Property {
        awsKey, awsSecret, awsKeyPairName, awsRegion, privateKeyFile, openvpnPassword, cloudflareAPIKey, cloudflareEmail, cloudflareTargetDomain, cloudflareSubdomain
    }

    /**
     * A {@code PrintStream} that redirects to {@code System.out} but cannot be closed.
     */
    private static class MyPrintStream extends PrintStream {
        /**
         * Creates a new print stream.  This stream will not flush automatically.
         *
         * @see PrintWriter#PrintWriter(OutputStream)
         */
        MyPrintStream() {
            super(System.out);
        }

        @Override
        public void close() {
            // do nothing to prevent closure
        }
    }
}
