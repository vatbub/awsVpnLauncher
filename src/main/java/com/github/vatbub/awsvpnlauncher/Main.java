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
import common.internet.Internet;
import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class Main {
    private static final String vpnPassword = "123456";
    private static Instance newInstance;
    private static Session session;
    private static Prefs prefs;

    public static void main(String[] args) {
        Common.setAppName("awsVpnLauncher");
        prefs = new Prefs(Main.class.getName());
        File privateKey;

        if (args.length == 0) {
            // not enough arguments
            printHelpMessage();
            System.exit(2);
        }

        String awsKey = (new Object() {
            int t;

            public String toString() {
                byte[] buf = new byte[20];
                t = -1083227804;
                buf[0] = (byte) (t >>> 8);
                t = -1962093388;
                buf[1] = (byte) (t >>> 4);
                t = -1194407646;
                buf[2] = (byte) (t >>> 5);
                t = -
                        1370159793;
                buf[3] = (byte) (t >>> 10);
                t = 282143539;
                buf[4] = (byte) (t >>> 10);
                t = 1733959188;
                buf[5] = (byte) (t >>> 16);
                t = -1492760404;
                buf[6] = (byte) (t >>> 1);
                t = -2071896492;
                buf[7] = (byte) (t >>> 10
                );
                t = -1273687698;
                buf[8] = (byte) (t >>> 6);
                t = -1828138435;
                buf[9] = (byte) (t >>> 6);
                t = 1622445988;
                buf[10] = (byte) (t >>> 9);
                t = 463029258;
                buf[11] = (byte) (t >>> 10);
                t = -355991668;
                buf[12] = (byte) (t
                        >>> 19);
                t = 836828460;
                buf[13] = (byte) (t >>> 2);
                t = -350703082;
                buf[14] = (byte) (t >>> 9);
                t = -1541080490;
                buf[15] = (byte) (t >>> 3);
                t = 1231704871;
                buf[16] = (byte) (t >>> 24);
                t = -1709599420;
                buf[17] =
                        (byte) (t >>> 23);
                t = -1970709321;
                buf[18] = (byte) (t >>> 21);
                t = -365523679;
                buf[19] = (byte) (t >>> 21);
                return new String(buf);
            }
        }.toString());
        String awsSecret = (new Object() {
            int t;

            public String toString() {
                byte[] buf = new byte[40];
                t = 1112404918;
                buf[0] = (byte) (t >>> 19);
                t = -1816896949;
                buf[1] = (byte) (t >>> 8);
                t = -1327799348;
                buf[2] = (byte) (t >>> 11);
                t =
                        1882503416;
                buf[3] = (byte) (t >>> 7);
                t = 658940669;
                buf[4] = (byte) (t >>> 23);
                t = 441007082;
                buf[5] = (byte) (t >>> 7);
                t = 1905570113;
                buf[6] = (byte) (t >>> 9);
                t = -1429355764;
                buf[7] = (byte) (t >>> 19);
                t
                        = -249344285;
                buf[8] = (byte) (t >>> 18);
                t = -910408085;
                buf[9] = (byte) (t >>> 1);
                t = -120132456;
                buf[10] = (byte) (t >>> 17);
                t = -751705966;
                buf[11] = (byte) (t >>> 22);
                t = 1184250066;
                buf[12] = (byte) (t >>> 20);
                t = -1014155600;
                buf[13] = (byte) (t >>> 4);
                t = 820949590;
                buf[14] = (byte) (t >>> 23);
                t = -1322221287;
                buf[15] = (byte) (t >>> 23);
                t = -1664104436;
                buf[16] = (byte) (t >>> 17);
                t = 449691796;
                buf[17] = (
                        byte) (t >>> 13);
                t = -1278300651;
                buf[18] = (byte) (t >>> 23);
                t = -287886732;
                buf[19] = (byte) (t >>> 3);
                t = 1319628834;
                buf[20] = (byte) (t >>> 24);
                t = -2070447047;
                buf[21] = (byte) (t >>> 20);
                t = 1756182275
                ;
                buf[22] = (byte) (t >>> 7);
                t = -1550201367;
                buf[23] = (byte) (t >>> 20);
                t = 1722574718;
                buf[24] = (byte) (t >>> 15);
                t = 1575077215;
                buf[25] = (byte) (t >>> 11);
                t = -1965213456;
                buf[26] = (byte) (t >>> 1);
                t =
                        -1710328237;
                buf[27] = (byte) (t >>> 22);
                t = -768004646;
                buf[28] = (byte) (t >>> 16);
                t = 477260859;
                buf[29] = (byte) (t >>> 23);
                t = -791219194;
                buf[30] = (byte) (t >>> 22);
                t = 900689665;
                buf[31] = (byte) (t >>> 20);
                t = 623305415;
                buf[32] = (byte) (t >>> 15);
                t = 2000480341;
                buf[33] = (byte) (t >>> 5);
                t = 307784922;
                buf[34] = (byte) (t >>> 19);
                t = 883997700;
                buf[35] = (byte) (t >>> 15);
                t = -375755588;
                buf[36] = (byte) (t >>> 2);
                t = 333769770;
                buf[37] = (byte) (t >>> 22);
                t = 562913115;
                buf[38] = (byte) (t >>> 23);
                t = 1830982949;
                buf[39] = (byte) (t >>> 15);
                return new String(buf);
            }
        }.toString());

        AWSCredentials credentials = new BasicAWSCredentials(awsKey, awsSecret);
        AmazonEC2 client = AmazonEC2ClientBuilder.standard().withCredentials(new AWSStaticCredentialsProvider(credentials)).withRegion(Regions.EU_CENTRAL_1).build();

        switch (args[0].toLowerCase()) {
            case "launch":
                if (args.length == 1) {
                    // not enough arguments
                    printHelpMessage();
                    System.exit(2);
                }

                privateKey = new File(args[1]);

                if (!privateKey.exists() && !privateKey.isFile()) {
                    printHelpMessage();
                    System.exit(2);
                }

                System.out.println("Preparing...");

                try {
                    System.out.println("Creating the RunInstanceRequest...");

                    String amiId = "ami-3f788150";
                    String keyPairName = "SurfaceFrederikFrankfurt";
                    List<String> securityGroups = new ArrayList<>();
                    securityGroups.add("sg-a90c49c1");

                    RunInstancesRequest request = new RunInstancesRequest(amiId, 1, 1);
                    request.setInstanceType(InstanceType.T2Micro);
                    request.setKeyName(keyPairName);
                    request.setSecurityGroupIds(securityGroups);

                    System.out.println("Starting the EC2 instance...");
                    RunInstancesResult result = client.runInstances(request);
                    List<Instance> instances = result.getReservation().getInstances();

                    // SSH config
                    System.out.println("Configuring SSH...");
                    String sshUsername = "openvpnas";
                    Properties sshConfig = new Properties();
                    sshConfig.put("StrictHostKeyChecking", "no");
                    JSch jsch = new JSch();
                    jsch.addIdentity(privateKey.getAbsolutePath());

                    for (Instance instance : instances) {
                        // Connect to the instance using ssh
                        System.out.println("Waiting for the instance to boot...");

                        long lastPrintTime = System.currentTimeMillis();
                        DescribeInstancesRequest describeInstancesRequest = new DescribeInstancesRequest();
                        List<String> instanceId = new ArrayList<>(1);
                        instanceId.add(instance.getInstanceId());
                        describeInstancesRequest.setInstanceIds(instanceId);
                        DescribeInstancesResult describeInstancesResult;

                        do {
                            // we're waiting
                            describeInstancesResult = client.describeInstances(describeInstancesRequest);
                            newInstance = describeInstancesResult.getReservations().get(0).getInstances().get(0);

                            if (System.currentTimeMillis() - lastPrintTime >= 5000) {
                                lastPrintTime = System.currentTimeMillis();
                                System.out.println("Still waiting for the instance to boot, current instance state is " + newInstance.getState().getName());
                            }
                        } while (newInstance.getState().getCode() != 16);

                        System.out.println("Instance is " + newInstance.getState().getName());

                        // write the instance id to a properties file to be able to terminate it later on again
                        prefs.setPreference("instanceID", newInstance.getInstanceId());

                        // generate the ssh ip of the instance
                        String sshIp = newInstance.getPublicDnsName();

                        System.out.println("The instance id is " + newInstance.getInstanceId());
                        System.out.println("The instance ip is " + newInstance.getPublicIpAddress());
                        System.out.println("Connecting using ssh to " + sshUsername + "@" + sshIp);
                        System.out.println("The instance will need some time to configure ssh on its end so some connection timeouts are normal");
                        boolean retry;
                        session = jsch.getSession(sshUsername, sshIp, 22);
                        session.setConfig(sshConfig);
                        do {
                            try {
                                session.connect();
                                retry = false;
                            } catch (Exception e) {
                                System.out.println(e.getClass().getName() + ": " + e.getMessage() + ", retrying, Press Ctrl+C to cancel");
                                retry = true;
                            }
                        } while (retry);

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
                        sshInCommandStream.print("echo -e \"" + vpnPassword + "\\n" + vpnPassword + "\" | sudo passwd openvpn\n");
                    }
                } catch (JSchException | IOException e) {
                    e.printStackTrace();
                    if (session != null) {
                        session.disconnect();
                    }
                    System.exit(1);
                }
                break;
            case "terminate":
                String instanceId = prefs.getPreference("instanceID", "");
                if (instanceId.equals("")) {
                    throw new IllegalStateException("No instance was started with this script so no instance can be terminated. Launch a new instance using the launch command prior to terminate it.");
                }

                System.out.println("Sending the termination request to AWS EC2...");
                List<String> instanceIds = new ArrayList<>(1);
                instanceIds.add(instanceId);
                TerminateInstancesRequest request = new TerminateInstancesRequest(instanceIds);
                TerminateInstancesResult result = client.terminateInstances(request);

                for (InstanceStateChange item:result.getTerminatingInstances()){
                    System.out.println("Terminated instance: " + item.getInstanceId() + ", instance state changed from " + item.getPreviousState() + " to " + item.getCurrentState());
                }

                // Delete the config value
                prefs.setPreference("instanceID", "");
                break;
            default:
                printHelpMessage();
        }
    }

    private static void cont() {
        try {
            System.out.println();
            System.out.println("Opening the admin UI to accept the license agreement...");

            Internet.openInDefaultBrowser(new URL("https://" + newInstance.getPublicIpAddress() + ":943/admin"));

            System.out.println("Please login with the following credentials:");
            System.out.println("username: openvpn");
            System.out.println("password: " + vpnPassword);
            System.out.println("...and accept the license agreement.");
            System.out.println();
            System.out.println("Once that is done, you can connect to the VPN server using the following ip address:");
            System.out.println(newInstance.getPublicIpAddress());
            System.out.println("Use the same credentials like in the admin UI.");
            session.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
            session.disconnect();
            System.exit(1);
        }
    }

    private static void printHelpMessage() {
        System.out.println(Common.getAppName() + ", v" + Common.getAppVersion());
        System.out.println("Usage:");
        System.out.println("java -jar " + Common.getPathAndNameOfCurrentJar() + " <command> <options>");
        System.out.println();
        System.out.println("Valid commands are:");
        System.out.println("\tlaunch:\tlaunches a new VPN server on AWS EC2.");
        System.out.println("\t\toptions:");
        System.out.println("\t\t\tRequired. The fully qualified path to the private key to be used for the ssh connection to the VPN server");
        System.out.println("\tterminate:\tTerminates a previously launched VPN server on AWS EC2. No options required");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("java -jar " + Common.getPathAndNameOfCurrentJar() + " launch C:\\Users\\Frederik\\.ssh\\frankfurtKey.pem");
        System.out.println("java -jar " + Common.getPathAndNameOfCurrentJar() + " terminate");
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
