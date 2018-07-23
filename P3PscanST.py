"""Scans URLs for P3P policies."""

import sys
import os
from lxml import html
import requests
import xmltodict
from xml.parsers.expat import ExpatError
import re


def getRef(linkRef):
    """
    Gets a link to a reference file. If a policy reference exists at the link,
    it is written to a report file and the global variable 'p3pxml' is set to
    '1'. Then the function tries to fetch the link to the location of
    p3p-policies valid for the given url. If a link to a
    policy is found it's passed to the getPolicy() function.

    The http header of the 'well known location' is written to
    the global variable 'wkl'.
    """
    global p3pxml
    p3pxml = 0
    global p3pxmlVal
    p3pxmlVal = 0
    global p3pPol
    p3pPol = 0
    global p3pPolVal
    p3pPolVal = 0
    global wklHeader
    wklHeader = ''

    try:
        r = requests.get(linkRef, timeout=27)
    except requests.Timeout:
        print 'Connection Timeout'
        p3pxml = 0
        p3pxmlVal = 0
        p3pPol = 0
        return
    except requests.exceptions.SSLError:
        print 'SSL Error'
        try:
            r = requests.get('https://'+url+'/w3c/p3p.xml', timeout=27, verify=False)
        except requests.Timeout:
            print 'Connection Timeout'
            p3pxml = 0
            p3pxmlVal = 0
            p3pPol = 0
            return
        except:
            print 'Unexpected connection error'
            p3pxml = 0
            p3pxmlVal = 0
            p3pPol = 0
            return
    except requests.ConnectionError:
        prefix, sl, uri, w3c, xml = linkRef.split('/')
        try:
            r = requests.get('http://www.'+uri+'/w3c/p3p.xml', timeout=27)
        except requests.Timeout:
            print 'Connection Timeout'
            p3pxml = 0
            p3pxmlVal = 0
            p3pPol = 0
            return
        except:
            print 'Unexpected connection error'
            p3pxml = 0
            p3pxmlVal = 0
            p3pPol = 0
            return
    except:
        print 'Unexpected connection error'
        p3pxml = 0
        p3pxmlVal = 0
        p3pPol = 0
        return

    wklHeader = r.headers

    if r.status_code == 200:

        policyReference = r.text.encode('utf-8')
        p3Xml = True

        try:
            polRef = xmltodict.parse(policyReference)
        except ExpatError:
            print '* no valid xml found at ' + r.url
            p3Xml = False
        except:
            print '* unexpected error'
            p3Xml = False

        if p3Xml:

            p3 = open(os.path.join(reports, 'P3P-'+domain+'('+tld+').txt'), 'a')
            p3.write('-----'+'\n')
            p3.write(r.url+'\n')
            p3.write('-----'+'\n')
            p3.write(policyReference)
            p3.write('-----'+'\n')
            p3.close()

            print '* Policy Reference File found at ' + r.url

            p3pxml = 1

            try:
                linkPol = polRef['META']['POLICY-REFERENCES']['POLICY-REF']['@about']
                if linkPol[:1] == '#':
                    linkPol = r.url+linkPol
                else:
                    if 'http' not in linkPol:
                        if linkPol[:5] == '/w3c/':
                            linkPol = 'http://'+url+linkPol
                        else:
                            if linkPol[:1] == '/':
                                linkPol = 'http://'+url+'/w3c'+linkPol
                            else:
                                linkPol = 'http://'+url+'/w3c/'+linkPol
                print '   --> policy should be at: ' + linkPol
                p3pxmlVal = 1
                getPolicy(linkPol)
            except:
                try:
                    linkPol = polRef['META']['POLICY-REFERENCES']['POLICY-REF']
                    num_ref = len(linkPol)
                    for i in range(0, num_ref):
                        print '   --> policy should be at: ' + linkPol[i]['@about']
                        p3pxmlVal = 1
                        getPolicy(linkPol[i]['@about'])
                except:
                    print 'parsing error --> no valid Policy Reference File'
                    p3pxmlVal = 0
                    p3pPol = 0
                    return

        else:
            p3pxml = 0
            p3pPol = 0
            return
    else:
        print '   --> no link to a policy file found at: ' + r.url
        p3pxml = 0
        p3pPol = 0
        return


def getPolicy(linkPol):
    """
    Gets a link to a p3p policy and tries to fetch it. If a policy is found,
    it will be written to the respective report file for the given url and
    the global variable 'p3pPol' is set to '1'.
    """
    global p3pPol
    global p3pPolVal

    try:
        policy = requests.get(linkPol, timeout=27)
    except requests.Timeout:
        print 'Connection Timeout'
        return
    except:
        print 'try to connect to: ' + linkPol
        print '* unexpected connection error'
        return

    if policy.status_code == 200:
        print '* policy found at: ' + linkPol

        p3pPol = 1

        privacyPolicy = policy.text.encode('utf-8')
        p3 = open(os.path.join(reports, 'P3P-'+domain+'('+tld+').txt'), 'a')
        p3.write('-----'+'\n')
        p3.write('* policy found at: ' + linkPol + '\n')
        p3.write('-----'+'\n')
        p3.write(privacyPolicy)
        p3.write('-----'+'\n')
        p3.close()
        p3pPolVal = testPolValidity(privacyPolicy)
        if p3pPolVal == 1:
            print '   --> policy valid'
        else:
            print '   --> policy not valid'
        return
    else:
        #  print policy.status_code
        print '* !!!  no policy found at: ' + linkPol + '  !!!'
        p3pPol = 0
    return


def testPolValidity(policyF):
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
    try:
        policy = xmltodict.parse(policyF)
    except ExpatError:
        print '* no valid xml'
        sys.exit()
    except:
        print '* unexpected xml parsing error'
        sys.exit()

    root = policy.keys()[0]
    content = str(policy.values()[0])
    #  print json.dumps(policy.values()[0], sort_keys=False, indent=2)
    p3 = open(os.path.join(reports, 'P3P-'+domain+'('+tld+').txt'), 'a')
    p3.write('-----'+'\n')
    p3.write('Policy validity check:'+'\n')
    p3.write(' '+'\n')

    if 'META' not in root:
        if 'POLICIES' not in root:
            if 'POLICY' not in root:
                CheckRootError = 1
                p3.write('* RootElementError'+'\n')
            else:
                CheckRootError = 0
        else:
            CheckRootError = 0
    else:
        CheckRootError = 0

    if 'discuri' in content:
        DiscuriError = 0
    else:
        DiscuriError = 1
        p3.write('mandatory "discuri" not found!'+'\n')

    if 'ACCESS' in content:
        AccessError = 0
    else:
        AccessError = 1
        p3.write('mandatory <ACCESS> element not found!'+'\n')

    if 'DATA-GROUP' in content:
        if 'DATA' in content:
            DataError = 0
        else:
            DataError = 1
            p3.write('mandatory <DATA> element not found!'+'\n')
    else:
        DataError = 1
        p3.write('mandatory <DATA-GROUP> or <DATA> element not found!'+'\n')

    if 'DISPUTES' in content:
        DisputesError = 0
    else:
        DisputesError = 1
        p3.write('mandatory <DISPUTES> element not found!'+'\n')

    if 'ENTITY' in content:
        EntityError = 0
    else:
        EntityError = 1
        p3.write('mandatory <ENTITY> element not found!'+'\n')

    if 'POLICY' in content:
        PolicyError = 0
    else:
        if 'POLICY' in root:
            PolicyError = 0
        else:
            PolicyError = 1
            p3.write('mandatory <POLICY> element not found!'+'\n')

    if 'PURPOSE' in content:
        PurposeError = 0
    else:
        PurposeError = 1
        p3.write('mandatory <PURPOSE> element not found!'+'\n')

    if 'RECIPIENT' in content:
        RecipientError = 0
    else:
        RecipientError = 1
        p3.write('mandatory <RECIPIENT> element not found!'+'\n')

    if 'RETENTION' in content:
        RetentionError = 0
    else:
        RetentionError = 1
        p3.write('mandatory <RETENTION> element not found!'+'\n')

    ValidationError = CheckRootError + DiscuriError + AccessError + DataError + DisputesError + EntityError + PolicyError + PurposeError + RecipientError + RetentionError

    if ValidationError > 0:
        p3.write('\n'+'Policy not valid!'+'\n')
        p3.write('-----'+'\n')
        p3.close()
        return 0
    else:
        p3.write('\n'+'Policy valid!'+'\n')
        p3.write('-----'+'\n')
        p3.close()
        return 1


def testComPolValidity(compol):
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

    compolval = 1

    p3pheadCP = re.findall(r'CP="(.*?)"', compol)
    p3pheadPR = re.findall(r'policyref="(.*?)"', compol)

    if len(p3pheadCP) > 1:
        compolval = 0
        return compolval
    if len(p3pheadPR) > 1:
        compolval = 0
        return compolval
    if p3pheadPR:
        linkRef = p3pheadPR[0]
        if 'http' not in linkRef:
            if linkRef[:5] == '/w3c/':
                linkRef = 'http://'+url+linkRef
            else:
                if linkRef[:1] == '/':
                    linkRef = 'http://'+url+'/w3c'+linkRef
                else:
                    linkRef = 'http://'+url+'/w3c/'+linkRef
        print '* reference file should be at: ' + linkRef
        getRef(linkRef)

    if p3pheadCP:
        CPTokens = p3pheadCP[0].split(' ')
        for i in range(0, len(CPTokens)):
            if len(CPTokens[i]) > 4:
                compolval = 0
            else:
                pass

    return compolval


def testWKL(url):
    """
    Gets an url, compose an url of the 'well known location', pass it to the
    getRef() function to determine if a reference file and the respective
    p3p-policies exists for the given url.

    getRef() also gives back the http header of the 'well known location' and
    if it contains a compact policy, it's written to the report
    file and passed to testComPolValidity() to validate it.
    """
    global ComPolWkl
    global ComPolWklVal

    wkl = 'http://'+url+'/w3c/p3p.xml'

    getRef(wkl)

    if "P3P" in wklHeader:
        print '* compact policy found in http-header of "well known location"'
        p3 = open(os.path.join(reports, 'P3P-'+domain+'('+tld+').txt'), 'a')
        p3.write('-----'+'\n')
        p3.write('compact policy found in http-header of "well known location"\n')
        p3.write('-----'+'\n')
        p3.write(wklHeader['P3P'] + '\n')
        p3.close()

        ComPolWkl = 1

        copo = wklHeader['P3P']
        valid = testComPolValidity(copo)
        if valid:
            ComPolWklVal = 1
        else:
            ComPolWklVal = 0
    else:
        ComPolWkl = 0
        ComPolWklVal = 0
        if ComPolWkl == 0:
            if p3pxml == 0:
                print '* nothing found at "well known location"'
            else:
                print '* no compact policy in http-header of "well known location"'

    return


def testMainsite(url):
    """
    1. Looks for a 'Compact Policy' in http-header to find a link to a
    preference file and/or preferences for cookie handling
    2. Looks for a '<link rel="P3Pv1" href='-pattern in html to find a
    link to a preference file
    """

    global ComPolMaSi
    ComPolMaSi = 0
    global ComPolMaSiVal
    ComPolMaSiVal = 0

    try:
        r = requests.get('http://'+url, timeout=27)
    except requests.Timeout:
        print 'Connection Timeout'
        return
    except requests.exceptions.SSLError:
        print 'SSL Error'
        try:
            r = requests.get('https://'+url, timeout=27, verify=False)
        except requests.Timeout:
            print 'Connection Timeout'
            return
    except requests.ConnectionError:
        try:
            r = requests.get('http://www.'+url, timeout=27)
        except requests.Timeout:
            print 'Connection Timeout'
            return
        except:
            print 'Unexpected connection error'
            return
    except:
        print '* unexpected connection error'
        return

    if r.status_code == 404:
        print 'http://' + url + ': 404'
        return
    #  1
    if "P3P" in str(r.headers):
        print '* compact policy found in http-header of mainsite'
        p3 = open(os.path.join(reports, 'P3P-'+domain+'('+tld+').txt'), 'a')
        p3.write('-----'+'\n')
        p3.write('compact policy found in http-header of ' + url + '\n')
        p3.write('-----'+'\n')
        p3.write(r.headers['P3P'] + '\n')
        p3.close()

        ComPolMaSi = 1

        copo = r.headers['P3P']
        valid = testComPolValidity(copo)
        if valid:
            ComPolMaSiVal = 1
            print '   --> compact policy valid'
        else:
            ComPolMaSiVal = 0
            print '   --> compact policy INvalid'
    else:
        ComPolMaSiVal = 0
        print '* nothing found in http-header of mainsite'
    #  2
    if len(r.content) == 0:
        print 'empty site'
        return
    pht = html.fromstring(r.content)
    links = pht.xpath('//link[@rel="P3Pv1"]/@href')
    if len(links) > 0:
        linkRef = links[0]
        print linkRef
        policyLink = getRef(linkRef)
        print policyLink
    else:
        print '* no <LINK rel="P3Pv1" href=[...]> HTML pattern found'
        print ' '


""" --- main --- """

helptext = '\nusage: python P3PscanST.py [option] [ URL | file ]\n\nOptions and arguments:\n-h: print this help message and exit\n-u URL: test a single URL\nfile: test a list of URLs from a textfile\n'

if len(sys.argv) < 2:
    print 'get help with option "-h"'
    sys.exit()
if sys.argv[1] == '-h':
    print helptext
    sys.exit()
if sys.argv[1] == '-u':
    if len(sys.argv) < 3:
        print helptext
        sys.exit()
    else:
        url = sys.argv[2]
        list = False
else:
    listFile = sys.argv[1]

if list:
    urlList = open(listFile, 'r')
    num_domains = sum(1 for line in urlList)
    urlList.close()
else:
    urlList = str(url)
    num_domains = 1

if list:
    urlList = open(listFile, 'r')
    name, fx = str(listFile).split('.')
    reports = 'domainreports_'+name
else:
    reports = 'domainreport_'+url

try:
    os.mkdir(reports)
except Exception:
    pass

if list:
    p3pScanReport = open('p3pScanReport-' + name + '.csv', 'w')
else:
    p3pScanReport = open('p3pScanReport-' + url + '.csv', 'w')
p3pScanReport.write('URL, p3p.xml, Policy Reference valid?, P3P-Policy, P3P-Policy valid?, CP in WKL-Header, CP in WKL-Header valid?, CP in MainSite-Header, CP in MainSite-Header valid?' + '\n')
p3pScanReport.close()

for i in range(0, num_domains):
    print '-----------'
    print str(i+1)+'/'+str(num_domains)
    if list:
        url = urlList.readline().rstrip('\n')
        domain = (url.rsplit('.', 1))[0]
        tld = (url.rsplit('.', 1))[1]
    else:
        domain = (url.rsplit('.', 1))[0]
        tld = (url.rsplit('.', 1))[1]
    print '-----------'
    print ' '
    print url + ':'
    print ' '
    testWKL(url)
    testMainsite(url)
    if list:
        p3pScanReport = open('p3pScanReport-' + name + '.csv', 'a')
    else:
        p3pScanReport = open('p3pScanReport-' + url + '.csv', 'a')
    p3pScanReport.write(url+','+str(p3pxml)+','+str(p3pxmlVal)+','+str(p3pPol)+','+str(p3pPolVal)+','+str(ComPolWkl)+','+str(ComPolWklVal)+','+str(ComPolMaSi)+','+str(ComPolMaSiVal)+'\n')
    p3pScanReport.close()


if list:
    urlList.close()
