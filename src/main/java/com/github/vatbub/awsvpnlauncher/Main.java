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
import com.jcraft.jsch.Channel;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import common.Common;
import common.Prefs;
import logging.FOKLogger;
import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

public class Main {
    // internal config
    private static final String securityGroupName = "AWSVPNSecurityGroup";
    private static final String sshUsername = "openvpnas";
    private static final String adminUsername = "openvpn";

    private static Instance newInstance;
    private static Session session;
    private static Prefs prefs;
    private static AmazonEC2 client;
    private static Regions awsRegion;
    private static String vpnUser;
    private static String vpnPassword;

    public static void main(String[] args) {
        Common.setAppName("awsVpnLauncher");
        prefs = new Prefs(Main.class.getName());

        if (args.length == 0) {
            // not enough arguments
            printHelpMessage();
            throw new NotEnoughArgumentsException();
        }

        switch (args[0].toLowerCase()) {
            case "launch":
                initAWSConnection();
                launch();
                break;
            case "terminate":
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
            default:
                printHelpMessage();
        }
    }

    private static void initAWSConnection() {
        AWSCredentials credentials = new BasicAWSCredentials(internalGetConfig(Property.awsKey), internalGetConfig(Property.awsSecret));
        awsRegion = Regions.valueOf(internalGetConfig(Property.awsRegion));
        client = AmazonEC2ClientBuilder.standard().withCredentials(new AWSStaticCredentialsProvider(credentials)).withRegion(awsRegion).build();
    }

    private static String getAmiId(Regions region) {
        /*
        US East (Virginia) - ami-bc3566ab
        US East (Ohio) - ami-10306a75
        US West (Oregon) - ami-d3e743b3
        US West (Northern California) - ami-4a02492a
        EU West (Ireland) - ami-f53d7386
        EU Central (Frankurt) - ami-ad1fe6c2
        Asia Pacific (Singapore) - ami-a859ffcb
        Asia Pacific (Tokyo) - ami-e9da7c88
        Asia Pacific (Sydney) - ami-89477aea
        South America (Sao Paulo) - ami-0c069b60
         */

        switch (region) {
            case US_EAST_1:
                return "ami-bc3566ab";
            case US_EAST_2:
                return "ami-10306a75";
            case US_WEST_1:
                return "ami-4a02492a";
            case US_WEST_2:
                return "ami-d3e743b3";
            case EU_WEST_1:
                return "ami-f53d7386";
            case EU_CENTRAL_1:
                return "ami-ad1fe6c2";
            case AP_SOUTHEAST_1:
                return "ami-a859ffcb";
            case AP_SOUTHEAST_2:
                return "ami-89477aea";
            case AP_NORTHEAST_1:
                return "ami-e9da7c88";
            default:
                throw new RegionNotSupportedException(region);
        }
    }

    private static void launch() {
        File privateKey = new File(internalGetConfig(Property.privateKeyFile));
        vpnUser = internalGetConfig(Property.openvpnUsername);
        vpnPassword = internalGetConfig(Property.openvpnPassword);

        if (!privateKey.exists() && !privateKey.isFile()) {
            throw new IllegalArgumentException("The file specified as " + Property.privateKeyFile.toString() + " does not exist or is not a file.");
        }

        FOKLogger.info(Main.class.getName(), "Preparing...");

        try {
            // Check if our security group exists already
            FOKLogger.info(Main.class.getName(), "Checking for the required security group...");
            DescribeSecurityGroupsRequest describeSecurityGroupsRequest = new DescribeSecurityGroupsRequest().withGroupNames(securityGroupName);
            DescribeSecurityGroupsResult describeSecurityGroupsResult = client.describeSecurityGroups(describeSecurityGroupsRequest);
            List<String> securityGroups = new ArrayList<>();

            String securityGroupId = "";
            for (SecurityGroup securityGroup : describeSecurityGroupsResult.getSecurityGroups()) {
                if (securityGroup.getGroupName().equals(securityGroupName)) {
                    securityGroupId = securityGroup.getGroupId();
                }
            }

            if (securityGroupId.equals("")) {
                // create the security group
                FOKLogger.info(Main.class.getName(), "Creating the required security group...");
                CreateSecurityGroupRequest createSecurityGroupRequest = new CreateSecurityGroupRequest()
                        .withGroupName(securityGroupName)
                        .withDescription("This security group was automatically created to run a OpenVPN Access Server.");
                client.createSecurityGroup(createSecurityGroupRequest);

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
                        new AuthorizeSecurityGroupIngressRequest().withGroupName("JavaSecurityGroup")
                                .withIpPermissions(sshPermission1)
                                .withIpPermissions(sshPermission2)
                                .withIpPermissions(httpsPermission1)
                                .withIpPermissions(httpsPermission2);
                client.authorizeSecurityGroupIngress(authorizeSecurityGroupIngressRequest);
                FOKLogger.info(Main.class.getName(), "The required security group has been successfully created!");
            } else {
                FOKLogger.info(Main.class.getName(), "The required security group already exists, we can continue");
                securityGroups.add(securityGroupId);
            }

            FOKLogger.info(Main.class.getName(), "Creating the RunInstanceRequest...");
            RunInstancesRequest request = new RunInstancesRequest(getAmiId(awsRegion), 1, 1);
            request.setInstanceType(InstanceType.T2Micro);
            request.setKeyName(internalGetConfig(Property.awsKeyPairName));
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
                sshInCommandStream.print("echo -e \"" + vpnPassword + "\\n" + vpnPassword + "\" | sudo passwd " + adminUsername + "\n");
            }
        } catch (JSchException | IOException e) {
            e.printStackTrace();
            if (session != null) {
                session.disconnect();
            }
            System.exit(1);
        }
    }

    private static void cont() {
        try {
            System.out.println();
            System.out.println();
            FOKLogger.info(Main.class.getName(), "----------------------------------------------------------------------");
            FOKLogger.info(Main.class.getName(), "Disconnecting the SSH-session...");
            FOKLogger.info(Main.class.getName(), "----------------------------------------------------------------------");

            List<String> endMessage = new ArrayList<>();
            endMessage.add("You can now connect to the VPN server using the following ip address:");
            endMessage.add(newInstance.getPublicIpAddress());
            endMessage.add("vpn-username: " + vpnUser);
            endMessage.add("vpn-password: " + vpnPassword);
            endMessage.add("admin-username: " + adminUsername);
            endMessage.add("admin-password: " + vpnPassword);

            FOKLogger.info(Main.class.getName(), "#########################################################################");
            for (String line:endMessage){
                FOKLogger.info(Main.class.getName(),"# " + line + getRequiredSpaces(line) + " #");
            }
            FOKLogger.info(Main.class.getName(), "#########################################################################");
            session.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
            session.disconnect();
            System.exit(1);
        }
    }

    private static String getRequiredSpaces(String message){
        String res = "";
        final String reference = "#########################################################################";
        int requiredSpaces = reference.length()-message.length()-4;

        for (int i=0; i<requiredSpaces; i++){
            res = res + " ";
        }

        return res;
    }

    private static void terminate() {
        String instanceIdsPrefValue = prefs.getPreference("instanceIDs", "");
        if (instanceIdsPrefValue.equals("")) {
            throw new IllegalStateException("No instance was started with this script so no instance can be terminated. Launch a new instance using the launch command prior to terminate it.");
        }

        FOKLogger.info(Main.class.getName(), "Sending the termination request to AWS EC2...");
        List<String> instanceIds = Arrays.asList(instanceIdsPrefValue.split(";"));
        TerminateInstancesRequest request = new TerminateInstancesRequest(instanceIds);
        TerminateInstancesResult result = client.terminateInstances(request);

        for (InstanceStateChange item : result.getTerminatingInstances()) {
            FOKLogger.info(Main.class.getName(), "Terminated instance: " + item.getInstanceId() + ", instance state changed from " + item.getPreviousState() + " to " + item.getCurrentState());
        }

        // Delete the config value
        prefs.setPreference("instanceIDs", "");
    }

    private static void printHelpMessage() {
        FOKLogger.info(Main.class.getName(), Common.getAppName() + ", v" + Common.getAppVersion());
        FOKLogger.info(Main.class.getName(), "Usage:");
        FOKLogger.info(Main.class.getName(), "java -jar " + Common.getPathAndNameOfCurrentJar() + " <command> <options>");
        FOKLogger.info(Main.class.getName(), "");
        FOKLogger.info(Main.class.getName(), "Valid commands are:");
        FOKLogger.info(Main.class.getName(), "\tlaunch:\tlaunches a new VPN server on AWS EC2.");
        FOKLogger.info(Main.class.getName(), "\t\toptions:");
        FOKLogger.info(Main.class.getName(), "\t\t\tRequired. The fully qualified path to the private key to be used for the ssh connection to the VPN server");
        FOKLogger.info(Main.class.getName(), "\tterminate:\tTerminates a previously launched VPN server on AWS EC2. No options required");
        FOKLogger.info(Main.class.getName(), "");
        FOKLogger.info(Main.class.getName(), "Examples:");
        FOKLogger.info(Main.class.getName(), "java -jar " + Common.getPathAndNameOfCurrentJar() + " launch C:\\Users\\Frederik\\.ssh\\frankfurtKey.pem");
        FOKLogger.info(Main.class.getName(), "java -jar " + Common.getPathAndNameOfCurrentJar() + " terminate");
    }

    private static void config(Property property, String value) {
        prefs.setPreference(property.toString(), value);
        FOKLogger.info(Main.class.getName(), "Set the preference " + property.toString() + " to " + value);
    }

    private static void getConfig(Property property) {
        FOKLogger.info(Main.class.getName(), "Value of property " + property.toString() + " is: " + prefs.getPreference(property.toString(), "<not set>"));
    }

    private static String internalGetConfig(Property property) {
        String res = prefs.getPreference(property.toString(), "");
        if (res.equals("")) {
            throw new PropertyNotConfiguredException(property);
        } else {
            return res;
        }
    }

    public enum Property {
        awsKey, awsSecret, awsKeyPairName, awsRegion, privateKeyFile, openvpnUsername, openvpnPassword
    }

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
        public void write(@NotNull byte b[], int off, int len) {
            super.write(b, off, len);
            try {
                String s = new String(b, "US-ASCII");
                if (s.contains("password updated successfully")) {
                    // continue
                    cont();
                }
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }
    }
}
