# P3Pscan
Scripts to (mass-)scan URLs for implementation of P3P privacy policies.

With regard to the proposed W3C standard, the script:

* scans the _'well known location'_ (URL + '/w3c/p3p.xml') for a _Policy Reference File_ ('p3p.xml'). If a reference file is found, the script tries to fetch the corresponding policy and evaluates it against the standard,
* scans the HTTP headers from the main site and the _'well knokwn location'_ for the so called _Compact Policy_. If found, the validity of the policy is evaluated,
* scans the HTML from the main site to find a _'<link rel="P3Pv1" href='_-pattern. If such link is found, the script tries to fetch the corresponding policy and evaluates the validity regarding the standard.

The result of a scan is a *<p3pScanReport-[name_of_URL(-List)].csv>* file that contains a detailed report about each scanned URL with information on _WKL_, Headers, Links and the validity of the found (compact) policies. Furthermore, a *<domainreports[_name_of_URL(-List)]>* folder is created which contains records for each URL where a P3P artefact was found. The artefacts are recorded for later evaluation inside URL specific text files.

### Usage single thread version (P3PscanST.py)

    python P3PscanST.py [option] [ URL | file ]

    Options and arguments:
    -h: print a help message and exit
    -u URL: test a single URL
    file: test a list of URLs from a textfile

The provided text file must contain a list of URLs, one per line. See the _testlist_ folder for examples.

### Usage multi thread version (P3PscanMT.py)

    python P3PscanMT.py [option] [ file ]

    Options and arguments:
    -h: print a help message and exit
    file: test a list of URLs from a textfile

To test a list of URLS provide a text file where each line consists of the tuple "rank,url" (like e.g. ["top-1m.csv"](http://s3.amazonaws.com/alexa-static/top-1m.csv.zip) from alexa). See the _testlist_ folder for examples.


### Notes

* This is just a little playground to get an idea about the adoption of P3P on the web.

* Particulary, the multi threaded version is just a PoC that needs some improvement. E.g. for large lists of URLs, the filling of the _qURL_ queue should be done in batches performed by another group of multithreaded workers.
