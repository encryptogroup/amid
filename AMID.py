#Copyright (c) 2011 by Thomas Poeppelmann and Thomas Schneider

# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish, dis-
# tribute, sublicense, and/or sell copies of the Software, and to permit
# persons to whom the Software is furnished to do so, subject to the fol-
# lowing conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABIL-
# ITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
# SHALL THE AUTHOR BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.


message ='''======================
AMI aiD (AMID)

This script scans your system for security or privacy critical data before publishing or when started as Amazon Machine Image (AMI).

The script will not change any files and does not communicate over the Internet. Please run the script as "root" user for read access to all directories and files.

The script gives recommendations to protect
- the Publisher (P) of the AMI not to include private data when publishing the AMI and
- the Consumer (C) of the AMI to remove security vulnerabilities when running the AMI.

Note: This script finds only the most important security and privacy critical data in AMIs. For details follow "Sharing AMIs Safely" in http://awsdocs.s3.amazonaws.com/EC2/latest/ec2-ug.pdf

(c) 2011 by Thomas Poeppelmann <thomas.poeppelmann@rub.de> and Thomas Schneider <thomas.schneider@trust.cased.de>
======================
'''

import os
import re
from datetime import datetime


def get_user_dirs(base_path):
    '''
    Returns all directories of users and the directory of root
    '''
    
    home_dirs = os.path.join(base_path, "home")
    dirs = []
    result =[]
    
    root_dir = os.path.join(base_path,"root")
    if os.path.exists(root_dir):
        result.append((root_dir, "root"))
    

    if os.path.exists(home_dirs):
        dirs = os.listdir(home_dirs),
        for user in dirs[0]:
            if(user != ".svn"):
                user_dir = os.path.join(home_dirs, user)
                result.append((user_dir, user))
    return result
            
def print_header(text):
    print "---------"
    print text
    print "---------"
         
          
################### Key Search ###################
def attack_dir(dir):  
    '''
    Searches for filename patterns in the /home and the /root directories that might indicate a private key
    '''
    
    found_list = []
    interesting = ('.*\.priv', '.*\.pem' , '.*id_rsa.*', ".*\.gpg", ".*\.jks")
    
    if os.path.exists(dir):
        for root, dirs, files in os.walk(dir):
            found_list = []
            for file in files:
                for pattern in interesting:
                    if (re.match(pattern, file) != None):
                        found_list.append([os.path.join(root, file ),file])
                        break 
    return found_list
    
    
def find_private_keys(base_path = "/"):
    '''
    Returns a list of files suspected to contain private keys. 
    Works by applying patterns to the filename an path. This may lead to 
    false-positives which have to be filtered later on.
    '''
    
    user_dirs = get_user_dirs(base_path)
    results = []
    
    for (user_dir, user_name) in user_dirs:
        for entry in attack_dir(user_dir):
            entry.append(user_name)
            results.append(entry)
        
    return results
    

def identfiy_AWS_key(filename):
    '''
    Amazon created AWS keys have a specific original filename e.g. pk-DASDA3...DAD3.pem
    This function tests for this pattern
    '''
     
    if (re.match("pk-[A-Za-z0-9]{2,100}", filename) != None):
        return True
    else:
        return False

    
def output_private_keys(findings):
    '''
    Prints found keys to the screen
    '''
       
    print_header("Private Keys")
    
    potential_AWS_keys = []
    potential_other_keys = []
    
    #no Findigns
    if len(findings) == 0:
        print ""
        print "None."
        print ""
    #Something found
    else:
        #Try to find AWS-API keys with filename pattern of pk-ADSK3DA...DAJS783.pem
        for finding in findings:
            if identfiy_AWS_key(finding[1]) == True:
                potential_AWS_keys.append(finding)
            else:
                #all other keys
                potential_other_keys.append(finding)
                
        if len(potential_AWS_keys) > 0:
            print "This AMI may contain the following AWS API Keys:"
            for entry in potential_AWS_keys:
                print entry[1] + " at " + entry[0]
            print ""
             
        if len(potential_other_keys) > 0:
            print "This AMI may contain the following private keys:"
            for entry in potential_other_keys:
                print entry[1] + " at " + entry[0]
            print ""
            
        print "P: Delete these keys before publishing"
        print ""            
        
     
############ SSH Authorized Keys ##############  
def find_ssh_authorized(base_path="/"):
    '''
    Searches for ssh_authorized files which may contain a backdoor (public key of AMI creator)
    '''
    result = find_file_in_home_dir(os.path.join(".ssh", "authorized_keys"), base_path, min_size=1)
    
    return result


def output_ssh_authorized(findings):
    '''
    Prints the findings regarding the backdoor in ssh_authorized
    '''
    
    print_header("SSH Backdoors (Authorized Keys)")
    
    if len(findings) > 0:
        print "The following files contain public keys that allow to log in via SSH:"
        for entry in findings:
            print entry
    
        print ""
        print "P: Do not include these files into the published AMI."
        print "C: Check that these files do not contain keys you do not know."
        print ""
    else:
        print ""
        print "None."
        print ""


############ SSH Host Keys ##############          
def find_SSH_host_keys(base_path="/"):
    '''
    Searches for SSH host keys
    '''
    
    ssh_hk_dir = os.path.join(base_path, "etc", "ssh")
    pattern = "ssh_host_.*"
    found_list = []
    for root, dirs, files in os.walk(ssh_hk_dir):
        for file in files:
            if (re.match(pattern, file) != None):
                path = os.path.join(root, file )
                stat = os.stat(path)
                fileage = datetime.fromtimestamp(stat.st_mtime)
                now = datetime.now()
                delta = now - fileage
            
                total_seconds = (delta.microseconds + (delta.seconds + delta.days * 24 * 3600) * 10**6) / 10**6                   
       
                found_list.append([path ,file, total_seconds])
                
    return found_list
                
                
def output_SSH_host_keys(findings):
    '''
    Prints the SSH host keys in the /etc/ssh folder on the screen
    '''
    
    print_header("SSH Host keys")
    
    if len(findings)>0:
        print "The following files contain keys for SSH host authentication:"
        
        for entry in findings:
            print entry[0] + " (age of file is " + str(entry[2]) + " seconds)"
    
        print ""
        print "P: Do not include these files into the published AMI."
        print "C: Check that these files have been freshly generated."
        print ""
    else:
        print ""
        print "None."
        print ""
    
    
def find_history(base_path="/"):
    '''
    Searches for the command line history .bash_history in the home dirs
    '''   
    
    result = find_file_in_home_dir(".bash_history", base_path, min_size=1)
    
    return result

def output_history(findings):
    '''
    Prints found .bash_history files on the screen
    '''
    
    print_header("Command-Line History")
    
    if len(findings)>0:
        print "The following files might contain a command line history with sensitive information (e.g., passwords)."
        
        for entry in findings:
            print entry
        
        print ""
        print "P: Remove these files before publishing the AMI."
        print ""
    else:
        print ""
        print "None."
        print ""


def find_file_in_home_dir(filepath, base_path="/", min_size=0):
    '''
    Searches for ssh_authorized files which can contain a backdoor (public key of AMI creator)
    '''
    
    user_dirs = get_user_dirs(base_path)
    results = []
    
    for home_dir, user in user_dirs:
        file = os.path.join(home_dir, filepath)
        #print authorized_file
        if os.path.isfile(file):
            if os.path.getsize(file) >= min_size:
                results.append(file)
    
    return results


def print_misc(base_path="/"):
    '''
    Output information on miscellaneous problems
    '''
    
    print_header("Miscellaneous")
    
    nothing_found = True
    #Boto configuration file
    result = find_file_in_home_dir(".boto", base_path, min_size=0)
    if len(result) >0:
        nothing_found = False
        print "The following file might contain configuration information and keys for the boto library"
        for entry in result:
            print entry
        
        print ""
        print "P: Remove this file before publishing."
        print ""
        
    result = find_file_in_home_dir(".ec2", base_path, min_size=0)
    if len(result) >0:
        nothing_found = False
        print "The following file might contain an ec2 configuration or AWS API keys"
        for entry in result:
            print entry
        
        print ""
        print "P: Remove this file before publishing."
        print ""
        
    if nothing_found == True:
        print ""
        print "None."
        print ""


def doit(base_path="/"):
    '''Execute all tests'''

    findings = find_private_keys(base_path)
    output_private_keys(findings)

    findings = find_ssh_authorized(base_path)
    output_ssh_authorized(findings)
    
    findings = find_history(base_path)
    output_history(findings)

    findings = find_SSH_host_keys(base_path)
    output_SSH_host_keys(findings)

    print_misc(base_path)
    
    
    
    
    
if __name__ == "__main__":
    print message
    print ""
    doit()
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    