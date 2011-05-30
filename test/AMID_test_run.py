'''
@author: thomas
'''
import unittest
import os
import sys


sys.path.insert(0, '..')
import AMID as antiAmazonIA



if __name__ == "__main__":
    test_cases = os.path.join(os.getcwd(),"", "full_test1")
    antiAmazonIA.doit(test_cases)
         
    print "######### END #########"

    
    #test_cases = os.path.join(os.getcwd(),"test", "full_test2")
    #antiAmazonIA.doit(test_cases)
    
    
    
    
    
    
    
    
    