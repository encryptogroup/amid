# AMI aiD (AMID)

Summary
-----
**Scanning a system for security or privacy critical data before publishing or when started as Amazon Machine Image (AMI)**


As [public AMIs often contain security or privacy critical information](http://trust.cased.de/AMID), we developed the AMID tool to detect the most important vulnerabilities in publicly available VM images.

The AMID tool scans your system for security or privacy critical data before publishing or when started as virtual machine in the cloud, e.g., an Amazon Machine Image (AMI).

Although the terminology we choose is based on that by the Amazon Web Services (AWS), AMID can be used also for other infrastructure-as-a-service (IAAS) cloud providers.

The script will not change any files and does not communicate over the Internet. Please run the script as "root" user for read access to all directories and files.

The script gives recommendations to protect
- the Publisher (P) of the AMI not to include private data when publishing the AMI and
- the Consumer (C) of the AMI to remove security vulnerabilities when running the AMI.

Note: This script finds only the most important security and privacy critical data in AMIs.

Features
-----
Tool issues a warning if the the following privacy relevant information is found in the users' home directories:

 * Bash History

 * Private Keys (Especially for AWS API)

 * Public SSH keys in .ssh/authorized_keys (backdoor)

 * .boto and .ec2 configuration files

In addition to that we scan for:
 
 * SSH host keys in /etc/ssh and their age (allows to determine if they are fresh)


Additional features
-----
Please feel free to participate!

 * Warning about log files

 * Warning on cached credentials in svn/hg/git repositories

Further information for manual protection
-----
  * AWS Documentation: [Sharing AMIs Safely](http://docs.amazonwebservices.com/AWSEC2/latest/UserGuide/index.html?AESDG-chapter-sharingamis.html)
  * AWS Security Bulletin (June 4, 2011): [Reminder about Safely Sharing and Using Public AMIs](http://aws.amazon.com/security/security-bulletins/reminder-about-safely-sharing-and-using-public-amis/)
  * AWS Tutorial (June 7, 2011): [How To Share and Use Public AMIs in A Secure Manner](http://aws.amazon.com/articles/0155828273219400)


(c) 2011 by Thomas Poeppelmann (thomas.poeppelmann@rub.de) and Thomas Schneider (thomas.schneider@ec-spride.de)
