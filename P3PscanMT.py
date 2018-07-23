"""Scans URLs for P3P policies."""

import sys
import os
from lxml import html
import requests
import xmltodict
from xml.parsers.expat import ExpatError
import re
import threading
import Queue
import time
import datetime

qURL = Queue.Queue()
qReport = Queue.Queue()


class P3PScanner(threading.Thread):

    def __init__(self, qURL, qReport):
        threading.Thread.__init__(self)
        self.qURL = qURL
        self.qReport = qReport

    def run(self):
        while True:
            print self.getName() + ' qsize: ' + str(self.qURL.qsize()) + '\n'
            self.urlRanks = self.qURL.get()
            print self.getName() + ' got: ' + self.urlRanks
            self.rank, self.url = (self.urlRanks.rstrip('\n').split(','))
            print self.url
            self.domain = (self.url.rsplit('.', 1))[0]
            self.tld = (self.url.rsplit('.', 1))[1]
            self.testWKL(self.url)
            self.testMainsite(self.url)

            self.result = (self.rank+','+self.url+','+str(self.p3pxml)+','+str(self.p3pxmlVal)+','+str(self.p3pPol)+','+str(self.p3pPolVal)+','+str(self.ComPolWkl)+','+str(self.ComPolWklVal)+','+str(self.ComPolMaSi)+','+str(self.ComPolMaSiVal))
            self.qReport.put(self.result)

            self.qURL.task_done()

    def getRef(self, linkRef):
        """
        Gets a link to a reference file. If a policy reference exists
        at the link, it is written to a report file and the
        variable 'p3pxml' is set to '1'. Then the function tries to
        fetch the link to the location of p3p-policies valid for the given url.
        If a link to a policy is found it's passed to the getPolicy() function.

        The http header of the 'well known location' is written to
        the variable 'wkl'.
        """
        self.linkRef = linkRef
        #  global p3pxml
        self.p3pxml = 0
        #  global p3pxmlVal
        self.p3pxmlVal = 0
        #  global p3pPol
        self.p3pPol = 0
        #  global p3pPolVal
        self.p3pPolVal = 0
        #  global wklHeader
        self.wklHeader = ''

        try:
            self.r = requests.get(self.linkRef, timeout=27)
        except requests.Timeout:
            print 'Connection Timeout'
            self.p3pxml = 0
            self.p3pxmlVal = 0
            self.p3pPol = 0
            return
        except requests.exceptions.SSLError:
            print 'SSL Error'
            try:
                self.r = requests.get('https://'+self.url+'/w3c/p3p.xml', timeout=27, verify=False)
            except requests.Timeout:
                print 'Connection Timeout'
                self.p3pxml = 0
                self.p3pxmlVal = 0
                self.p3pPol = 0
                return
            except:
                print 'Unexpected connection error'
                self.p3pxml = 0
                self.p3pxmlVal = 0
                self.p3pPol = 0
                return
        except requests.ConnectionError:
            self.prefix, self.sl, self.uri, self.w3c, self.xml = self.linkRef.split('/')
            try:
                self.r = requests.get('http://www.'+self.uri+'/w3c/p3p.xml', timeout=27)
            except requests.Timeout:
                print 'Connection Timeout'
                self.p3pxml = 0
                self.p3pxmlVal = 0
                self.p3pPol = 0
                return
            except:
                print 'Unexpected connection error'
                self.p3pxml = 0
                self.p3pxmlVal = 0
                self.p3pPol = 0
                return
        except:
            print 'Unexpected connection error'
            self.p3pxml = 0
            self.p3pxmlVal = 0
            self.p3pPol = 0
            return

        self.wklHeader = self.r.headers

        if self.r.status_code == 200:

            self.policyReference = self.r.text.encode('utf-8')
            self.p3Xml = True

            try:
                self.polRef = xmltodict.parse(self.policyReference)
            except ExpatError:
                print '* no valid xml found at ' + self.r.url
                self.p3Xml = False
            except:
                print '* unexpected error'
                self.p3Xml = False

            if self.p3Xml:

                self.p3 = open(os.path.join(reports, 'P3P-'+self.domain+'('+self.tld+').txt'), 'a')
                self.p3.write('-----'+'\n')
                self.p3.write(self.r.url+'\n')
                self.p3.write('-----'+'\n')
                self.p3.write(self.policyReference)
                self.p3.write('-----'+'\n')
                self.p3.close()

                print '* Policy Reference File found at ' + self.r.url

                self.p3pxml = 1

                try:
                    self.linkPol = self.polRef['META']['POLICY-REFERENCES']['POLICY-REF']['@about']
                    if self.linkPol[:1] == '#':
                        self.linkPol = self.r.url+self.linkPol
                    else:
                        if 'http' not in self.linkPol:
                            if self.linkPol[:5] == '/w3c/':
                                self.linkPol = 'http://'+self.url+self.linkPol
                            else:
                                if self.linkPol[:1] == '/':
                                    self.linkPol = 'http://'+self.url+'/w3c'+self.linkPol
                                else:
                                    self.linkPol = 'http://'+self.url+'/w3c/'+self.linkPol
                    print '   --> policy should be at: ' + self.linkPol
                    self.p3pxmlVal = 1
                    self.getPolicy(self.linkPol)
                except:
                    try:
                        self.linkPol = self.polRef['META']['POLICY-REFERENCES']['POLICY-REF']
                        self.num_ref = len(self.linkPol)
                        for i in range(0, self.num_ref):
                            print '   --> policy should be at: ' + self.linkPol[i]['@about']
                            self.p3pxmlVal = 1
                            self.getPolicy(self.linkPol[i]['@about'])
                    except:
                        print 'parsing error --> no valid Policy Reference File'
                        self.p3pxmlVal = 0
                        self.p3pPol = 0
                        return

            else:
                self.p3pxml = 0
                self.p3pPol = 0
                return
        else:
            print '   --> no link to a policy file found at: ' + self.r.url
            self.p3pxml = 0
            self.p3pPol = 0
            return

    def getPolicy(self, linkPol):
        """
        Gets a link to a p3p policy and tries to fetch it. If a policy is found,
        it will be written to the respective report file for the given url and
        the global variable 'p3pPol' is set to '1'.
        """
        #  global p3pPol
        #  global p3pPolVal

        self.linkPol = linkPol

        try:
            self.policy = requests.get(self.linkPol, timeout=27)
        except requests.Timeout:
            print 'Connection Timeout'
            return
        except:
            print 'try to connect to: ' + self.linkPol
            print '* unexpected connection error'
            return

        if self.policy.status_code == 200:
            print '* policy found at: ' + self.linkPol

            self.p3pPol = 1

            self.privacyPolicy = self.policy.text.encode('utf-8')
            self.p3 = open(os.path.join(reports, 'P3P-'+self.domain+'('+self.tld+').txt'), 'a')
            self.p3.write('-----'+'\n')
            self.p3.write('* policy found at: ' + self.linkPol + '\n')
            self.p3.write('-----'+'\n')
            self.p3.write(self.privacyPolicy)
            self.p3.write('-----'+'\n')
            self.p3.close()
            self.p3pPolVal = self.testPolValidity(self.privacyPolicy)
            if self.p3pPolVal == 1:
                print '   --> policy valid'
            else:
                print '   --> policy not valid'
            return
        else:
            #  print policy.status_code
            print '* !!!  no policy found at: ' + self.linkPol + '  !!!'
            self.p3pPol = 0
        return

    def testPolValidity(self, policyF):
        """
        gets a policy. to determine if it's valid runs following tests:
            * looks if root element of policy is either 'META', 'POLICY'
              or 'POLICIES'
            * looks if the mandatory attribute 'discuri' exists
            * looks if all of the mandatory elements '<ACCESS>',
            '<DATA-GROUP>', '<DATA>', '<DISPUTES>', '<ENTITY>', '<POLICY>',
            '<PURPOSE>', '<RECIPIENT>' & '<RETENTION>' exists
        if valid returns 1, returns 0 otherwise
        """

        self.policyF = policyF

        try:
            self.policy = xmltodict.parse(self.policyF)
        except ExpatError:
            print '* no valid xml'
            sys.exit()
        except:
            print '* unexpected xml parsing error'
            sys.exit()

        self.root = self.policy.keys()[0]
        self.content = str(self.policy.values()[0])
        #  print json.dumps(policy.values()[0], sort_keys=False, indent=2)
        self.p3 = open(os.path.join(reports, 'P3P-'+self.domain+'('+self.tld+').txt'), 'a')
        self.p3.write('-----'+'\n')
        self.p3.write('Policy validity check:'+'\n')
        self.p3.write(' '+'\n')

        if 'META' not in self.root:
            if 'POLICIES' not in self.root:
                if 'POLICY' not in self.root:
                    self.CheckRootError = 1
                    self.p3.write('* RootElementError'+'\n')
                else:
                    self.CheckRootError = 0
            else:
                self.CheckRootError = 0
        else:
            self.CheckRootError = 0

        if 'discuri' in self.content:
            self.DiscuriError = 0
        else:
            self.DiscuriError = 1
            self.p3.write('mandatory "discuri" not found!'+'\n')

        if 'ACCESS' in self.content:
            self.AccessError = 0
        else:
            self.AccessError = 1
            self.p3.write('mandatory <ACCESS> element not found!'+'\n')

        if 'DATA-GROUP' in self.content:
            if 'DATA' in self.content:
                self.DataError = 0
            else:
                self.DataError = 1
                self.p3.write('mandatory <DATA> element not found!'+'\n')
        else:
            self.DataError = 1
            self.p3.write('mandatory <DATA-GROUP> or <DATA> element not found!'+'\n')

        if 'DISPUTES' in self.content:
            self.DisputesError = 0
        else:
            self.DisputesError = 1
            self.p3.write('mandatory <DISPUTES> element not found!'+'\n')

        if 'ENTITY' in self.content:
            self.EntityError = 0
        else:
            self.EntityError = 1
            self.p3.write('mandatory <ENTITY> element not found!'+'\n')

        if 'POLICY' in self.content:
            self.PolicyError = 0
        else:
            if 'POLICY' in self.root:
                self.PolicyError = 0
            else:
                self.PolicyError = 1
                self.p3.write('mandatory <POLICY> element not found!'+'\n')

        if 'PURPOSE' in self.content:
            self.PurposeError = 0
        else:
            self.PurposeError = 1
            self.p3.write('mandatory <PURPOSE> element not found!'+'\n')

        if 'RECIPIENT' in self.content:
            self.RecipientError = 0
        else:
            self.RecipientError = 1
            self.p3.write('mandatory <RECIPIENT> element not found!'+'\n')

        if 'RETENTION' in self.content:
            self.RetentionError = 0
        else:
            self.RetentionError = 1
            self.p3.write('mandatory <RETENTION> element not found!'+'\n')

        self.ValidationError = self.CheckRootError + self.DiscuriError + self.AccessError + self.DataError + self.DisputesError + self.EntityError + self.PolicyError + self.PurposeError + self.RecipientError + self.RetentionError

        if self.ValidationError > 0:
            self.p3.write('\n'+'Policy not valid!'+'\n')
            self.p3.write('-----'+'\n')
            self.p3.close()
            return 0
        else:
            self.p3.write('\n'+'Policy valid!'+'\n')
            self.p3.write('-----'+'\n')
            self.p3.close()
            return 1

    def testComPolValidity(self, compol):
        """
        The P3P header syntax must be one of the followings:
        * P3P: CP="...", policyref="..."
        * P3P: policyref="...", CP="..."
        * P3P: CP="..."
        * P3P: policyref="..."
        ---
        'policyref="..."' contains ONE Link to a Policy Reference file
        'CP="..."' contains specified Compact Policy Tokens with len(Token)<=4
        ---
        If all the requirements above are met the compact policy seems valid and
        the variable compoval is set to '1'.

        The possily found link to a reference file is passed to the
        getRef() function.
        """
        self.compol = compol
        self.compolval = 1

        self.p3pheadCP = re.findall(r'CP="(.*?)"', self.compol)
        self.p3pheadPR = re.findall(r'policyref="(.*?)"', self.compol)

        if len(self.p3pheadCP) > 1:
            self.compolval = 0
            return self.compolval
        if len(self.p3pheadPR) > 1:
            self.compolval = 0
            return self.compolval
        if self.p3pheadPR:
            self.linkRef = self.p3pheadPR[0]
            if 'http' not in self.linkRef:
                if self.linkRef[:5] == '/w3c/':
                    self.linkRef = 'http://'+url+self.linkRef
                else:
                    if self.linkRef[:1] == '/':
                        self.linkRef = 'http://'+self.url+'/w3c'+self.linkRef
                    else:
                        self.linkRef = 'http://'+url+'/w3c/'+self.linkRef
            print '* reference file should be at: ' + self.linkRef
            self.getRef(self.linkRef)

        if self.p3pheadCP:
            self.CPTokens = self.p3pheadCP[0].split(' ')
            for i in range(0, len(self.CPTokens)):
                if len(self.CPTokens[i]) > 4:
                    self.compolval = 0
                else:
                    pass

        return self.compolval

    def testWKL(self, url):
        """
        Gets an url, compose an url of the 'well known location', pass it to the
        getRef() function to determine if a reference file and the respective
        p3p-policies exists for the given url.

        getRef() also gives back the http header of the 'well known location' and
        if it contains a compact policy, it's written to the report
        file and passed to testComPolValidity() to validate it.
        """
        #  global ComPolWkl
        #  global ComPolWklVal

        self.url = url

        self.wkl = 'http://'+self.url+'/w3c/p3p.xml'

        self.getRef(self.wkl)

        if "P3P" in self.wklHeader:
            print '* compact policy found in http-header of "well known location"'
            self.p3 = open(os.path.join(reports, 'P3P-'+self.domain+'('+self.tld+').txt'), 'a')
            self.p3.write('-----'+'\n')
            self.p3.write('compact policy found in http-header of "well known location"\n')
            self.p3.write('-----'+'\n')
            self.p3.write(self.wklHeader['P3P'] + '\n')
            self.p3.close()

            self.ComPolWkl = 1

            self.copo = self.wklHeader['P3P']
            self.valid = self.testComPolValidity(self.copo)
            if self.valid:
                self.ComPolWklVal = 1
            else:
                self.ComPolWklVal = 0
        else:
            self.ComPolWkl = 0
            self.ComPolWklVal = 0
            if self.ComPolWkl == 0:
                if self.p3pxml == 0:
                    print '* nothing found at "well known location"'
                else:
                    print '* no compact policy in http-header of "well known location"'

        return

    def testMainsite(self, url):
        """
        1. Looks for a 'Compact Policy' in http-header to find a link to a
        preference file and/or preferences for cookie handling
        2. Looks for a '<link rel="P3Pv1" href='-pattern in html to find a
        link to a preference file
        """

        self.url = url

        #  global ComPolMaSi
        self.ComPolMaSi = 0
        self.ComPolMaSiVal = 0

        try:
            self.r = requests.get('http://'+self.url, timeout=27)
        except requests.Timeout:
            print 'Connection Timeout'
            return
        except requests.exceptions.SSLError:
            print 'SSL Error'
            try:
                self.r = requests.get('https://'+self.url, timeout=27, verify=False)
            except requests.Timeout:
                print 'Connection Timeout'
                return
        except requests.ConnectionError:
            try:
                self.r = requests.get('http://www.'+self.url, timeout=27)
            except requests.Timeout:
                print 'Connection Timeout'
                return
            except:
                print 'Unexpected connection error'
                return
        except:
            print '* unexpected connection error'
            return

        if self.r.status_code == 404:
            print 'http://' + self.url + ': 404'
            return
        #  1
        if "P3P" in str(self.r.headers):
            print '* compact policy found in http-header of mainsite'
            self.p3 = open(os.path.join(reports, 'P3P-'+self.domain+'('+self.tld+').txt'), 'a')
            self.p3.write('-----'+'\n')
            self.p3.write('compact policy found in http-header of ' + self.url + '\n')
            self.p3.write('-----'+'\n')
            self.p3.write(self.r.headers['P3P'] + '\n')
            self.p3.close()

            self.ComPolMaSi = 1

            self.copo = self.r.headers['P3P']
            self.valid = self.testComPolValidity(self.copo)
            if self.valid:
                self.ComPolMaSiVal = 1
                print '   --> compact policy valid'
            else:
                self.ComPolMaSiVal = 0
                print '   --> compact policy INvalid'
        else:
            self.ComPolMaSiVal = 0
            print '* nothing found in http-header of mainsite'
        #  2
        if len(self.r.content) == 0:
            print 'empty site'
            return
        self.pht = html.fromstring(self.r.content)
        self.links = self.pht.xpath('//link[@rel="P3Pv1"]/@href')
        if len(self.links) > 0:
            self.linkRef = self.links[0]
            print self.linkRef
            self.policyLink = self.getRef(self.linkRef)
            print self.policyLink
        else:
            print '* no <LINK rel="P3Pv1" href=[...]> HTML pattern found'
            print ' '


class fileReporter(threading.Thread):
    def __init__(self, qReport):
        threading.Thread.__init__(self)
        self.qReport = qReport

    def run(self):
        while True:
            while not self.qReport.empty():
                print self.getName() + ' reporting'
                self.report = self.qReport.get()
                self.p3pScanReport = open('p3pScanReport-' + name + '.csv', 'a')
                self.p3pScanReport.write(self.report+'\n')
                self.p3pScanReport.close()
                self.qReport.task_done()


""" --- main --- """

helptext = '\nusage: python P3PscanMT.py [option] [ file ]\n\nOptions and arguments:\n-h: print this help message and exit\nfile: test a list of URLs from a textfile where each line consits of the tuple "rank,url" (e.g. "top-1m.csv" from alexa)\n'

if len(sys.argv) < 2:
    print 'get help with option "-h"'
    sys.exit()
if sys.argv[1] == '-h':
    print helptext
    sys.exit()

listFile = sys.argv[1]

urlList = open(listFile, 'r')
num_domains = sum(1 for line in urlList)
urlList.close()

urlList = open(listFile, 'r')
name, fx = str(listFile).split('.')
global reports
reports = 'domainreports_'+name

try:
    os.mkdir(reports)
except Exception:
    pass

num_threads = 10

for i in range(num_threads):
    P = P3PScanner(qURL, qReport)
    P.setDaemon(True)
    P.start()

for i in range(num_domains):
    rank, url = (urlList.readline().rstrip('\n').split(','))
    qURL.put(rank + ',' + url)

#  qURL.join()

p3pScanReport = open('p3pScanReport-' + name + '.csv', 'w')
p3pScanReport.write('Rank, URL, p3p.xml, p3p.xml valid?, P3P-Policy, P3P-Policy valid?, CP in WKL-Header, CP in WKL-Header valid?, CP in MainSite-Header, CP in MainSite-Header valid?' + '\n')
p3pScanReport.close()

for i in range(num_threads):
    R = fileReporter(qReport)
    R.setDaemon(True)
    R.start()

qURL.join()
qReport.join()

urlList.close()
