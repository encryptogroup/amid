# Introduction #

AMI aiD (AMID) - Scanning a system for security or privacy critical data before publishing or when started as virtual machine in the cloud, e.g., an Amazon Machine Image (AMI)


# Additional Information #
See also
  * [How To Share and Use Public AMIs in A Secure Manner ](http://aws.amazon.com/articles/0155828273219400)

  * [Reminder about Safely Sharing and Using Public AMIs ](http://aws.amazon.com/security/security-bulletins/reminder-about-safely-sharing-and-using-public-amis/)

  * [Sharing AMIs Safely](http://docs.amazonwebservices.com/AWSEC2/latest/UserGuide/index.html?AESDG-chapter-sharingamis.html)

# Features #
Tool issues a warning if the the following privacy relevant information is found in the users' home directories:

  * Bash History

  * Private Keys (Especially for AWS API)

  * Public SSH keys in .ssh/authorized\_keys (backdoor)

  * .boto and .ec2 configuration files

In addition to that we scan for:

  * SSH host keys in /etc/ssh and their age (allows to determine if they are fresh)


# Additional features #
Please feel free to participate!

  * Warning about log files

  * Warning on cached credentials in svn/hg/git repositories