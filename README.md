# awsVpnLauncher
This tool starts a new AWS EC2 instance and configures a ready to use OpenVPN Server on it in just 2 minutes.

## Download
We don't use GitHub releases, and publish on Bintray instead. You can download the binaries [here](https://bintray.com/vatbub/fokprojectsReleases/awsVpnLauncher#downloads).

## Initial config
1. [Setup your AWS Account](https://aws.amazon.com/) if you don't have one already
2. Go to [EC2](https://eu-central-1.console.aws.amazon.com/ec2/v2/home) and pick your desired region in the upper right corner. It is important to choose the right region as this will be the location shown to other websites while you use the VPN. If you want to appear to be in Germany, you need to select EU (Frankfurt). Likewise, you need to select EU (Ireland) to set your position to Ireland. 
  **Please note: ** VPN is only available in the following regions: 
  - US_EAST_1 (Virginia)
  - US_EAST_2 (Ohio)
  - US_WEST_1 (Northern California)
  - US_WEST_2 (Oregon)
  - CA_CENTRAL_1 (Canada)
  - EU_WEST_1 (Ireland)
  - EU_WEST_2 (London)
  - EU_CENTRAL_1 (Frankfurt)
  - AP_SOUTH_1 (Mumbai)
  - AP_SOUTHEAST_1 (Singapore)
  - AP_SOUTHEAST_2 (Sydney)
  - AP_NORTHEAST_1 (Tokyo)
  - AP_NORTHEAST_2 (Seoul)
  - SA_EAST_1 (Sao Paulo)
  *(For nerds: This is because the AMI is only available in those regions)*
3. Note the code of the region you chose (e. g. `AP_SOUTHEAST_2` for Sydney)
4. Head over to the "Key Pairs"-section in the left menu and create a new Key Pair. Note the name of the Key Pair and download the corresponding `pem` file. This file is used to authenticate on the new instances so keep it in a safe place where it is unlikely that you will delete the file.
5. Go to the [IAM User service](https://console.aws.amazon.com/iam/home?region=ap-southeast-2#/users) and create a new user.
6. Give it a good name and allow "Programmatic access" and do not allow "AWS Management Console access" for more security.
7. Select "Attach existing policies directly" on the permissions page and select "AmazonEC2FullAccess" *(Don't worry, we only create and terminate EC2 instances and the required security group, nothing else, but this is the only permission set that we tested the script with. If you don't trust us, have a look at the source code.)*
8. Click "Review" and "Create user". A "Access Key ID" and a "Secret access key" will be shown to you. Note them both down.
9. Now open up a terminal (on Windows, you hit Win+R and type cmd and then hit "Enter"). `cd` to the folder where you saved the downloaded file in.
10. Run the following commands and replace the parameter values with yours:
```cmd
java -jar awsVpnLauncher-1.4-jar-with-dependencies.jar config awsRegion <The code of the region you chose>
java -jar awsVpnLauncher-1.4-jar-with-dependencies.jar config awsKey <Your Access Key ID>
java -jar awsVpnLauncher-1.4-jar-with-dependencies.jar config awsSecret <Secret access Key>
java -jar awsVpnLauncher-1.4-jar-with-dependencies.jar config awsKeyPairName <The name of the key pair you created>
java -jar awsVpnLauncher-1.4-jar-with-dependencies.jar config privateKeyFile C:\path\to\the\private\keyFile.pem
java -jar awsVpnLauncher-1.4-jar-with-dependencies.jar config openvpnPassword <The password for the vpn server that you wish to use>
```

Note that all of your credentials and passwords will be stored on your hard drive in clear text. Nothing is sent to any server except to Amazon AWS.

## Launch a new instance
1. Open a terminal
2. `cd` to the downloaded `jar`-file
3. Run `java -jar awsVpnLauncher-1.4-jar-with-dependencies.jar launch`

## Terminate all running instances
1. Open a terminal
2. `cd` to the downloaded `jar`-file
3. Run `java -jar awsVpnLauncher-1.4-jar-with-dependencies.jar terminate`

## Pricing
The script itself is free and is provided under the [Apache License v2.0](https://github.com/vatbub/awsVpnLauncher/blob/master/LICENSE.txt). 
However, AWS will charge you for the required resources. The exact prices can be found [here](https://aws.amazon.com/marketplace/pp/B00MI40CAE/ref=mkt_wir_openvpn_byol#pricing-box).
We currently use t2.micro as the instance type but there are plans to make this configurable.

AWS will charge you for the traffic you push through the VPN, too. Detailed info about that can be found [here](https://aws.amazon.com/ec2/pricing/on-demand/#Data_Transfer).

The instance type t2.micro is [free tier eligible](https://aws.amazon.com/free/). That means that the cpu of the instance will be free for one year. However, you will still be charged for the traffic.

## Troubleshooting
### Things get stuck while launching/configuring the VPN server
Just hit `Ctrl+C` to cancel the launch, run the [terminate](#terminate-all-running-instances) command and then the [launch](#launch-a-new-instance) command again. If this does not work then, check if you are connected to the internet. If it still fails, create a new issue and post the console log in the issue. We will be pleased to help you.
