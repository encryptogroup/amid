'''
@author: thomas
'''
import unittest
import os
import sys


sys.path.insert(0, '..')
import AMID as antiAmazonIA


test_cases = os.path.join(os.getcwd(),"")

class Test(unittest.TestCase):

    
    def test_find_dirs(self):
        '''Test the function to find all home dirs'''
        
        #test_case = os.path.join(test_cases,"test1")
        #self.failUnlessEqual(antiAmazonIA.get_user_dirs(test_case),[(os.path.join(test_case,"root"),"root") , (os.path.join(test_case,"home","ec2-user"),"ec2-user"), (os.path.join(test_case,"home","user1"),"user1")])
    
        #test_case = os.path.join(test_cases,"test12")    
        #self.failUnlessEqual(antiAmazonIA.get_user_dirs(test_case),[(os.path.join(test_case,"home","ec2-user"),"ec2-user"), (os.path.join(test_case,"home","user1"),"user1")])
        
        #test_case = os.path.join(test_cases,"test13")
        #self.failUnlessEqual(antiAmazonIA.get_user_dirs(test_case),[(os.path.join(test_case,"root"),"root")])
        
        test_case = os.path.join(test_cases,"test14")
        self.failUnlessEqual(antiAmazonIA.get_user_dirs(test_case),[(os.path.join(test_case,"root"),"root")])
        
    def test_find_keys(self):
        test_case = os.path.join(test_cases,"test2")
        result = antiAmazonIA.find_private_keys(test_case)
        

        self.failUnlessEqual([os.path.join(test_case,"home","ec2-user", "secret" ,"key.priv"), 'key.priv', 'ec2-user'] in result, True)
        self.failUnlessEqual([os.path.join(test_case,"home","user2", "secring.gpg"), 'secring.gpg', 'user2'] in result, True)
        self.failUnlessEqual([os.path.join(test_case,"home","user2", "secret_id_rsa"), 'secret_id_rsa', 'user2'] in result, True)
        
        self.failUnlessEqual(len(result), 4)
        
    def test_identify_AWS_key(self):  
        self.failUnlessEqual(antiAmazonIA.identfiy_AWS_key("pk-JDHZENXYKNAFDSFGSGSFS.pem"), True)
        self.failUnlessEqual(antiAmazonIA.identfiy_AWS_key("pk-JDHZENXY4LS.pem"), True)
        self.failUnlessEqual(antiAmazonIA.identfiy_AWS_key("ldsad.pem"), False)
        self.failUnlessEqual(antiAmazonIA.identfiy_AWS_key("ec2_pk.pem"), False)

    def test_SSH_authorized(self):
        test_case = os.path.join(test_cases,"test4")
        self.failUnlessEqual(antiAmazonIA.find_ssh_authorized(test_case),[os.path.join(test_case,"home","ec2-user",".ssh","authorized_keys")])
        
        test_case = os.path.join(test_cases,"test41")
        self.failUnlessEqual(antiAmazonIA.find_ssh_authorized(test_case),[])
        
    def test_Host_keys(self):    
        test_case = os.path.join(test_cases,"test5")
        result = antiAmazonIA.find_SSH_host_keys(test_case)
        
        self.failUnlessEqual(result[0][1], "ssh_host_dsa_key")
        self.failUnlessEqual(len(result), 1)

    def test_history(self):    
        test_case = os.path.join(test_cases,"test6")
        result = antiAmazonIA.find_history(test_case)
        
        self.failUnlessEqual(result[0], os.path.join(test_case,"home", "ec2-user", ".bash_history"))
        self.failUnlessEqual(len(result), 1)



if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
    
    
    
    