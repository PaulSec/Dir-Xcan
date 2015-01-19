#!/usr/bin/python
# LAST UPDATE 18/12/14
#
# DIR-XCAN5.PY
# This program is for finding hidden directories that are not directly linked on a website. It find HTTP response code 200 directories and outputs the URL to file.

# THIS PROGRAM IS A PYTHON VERSION OF THE OWASP'S DIRBUSTER PROJECT THAT IS NOW CLOSED
# https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project
#
#   This script uses OWASP's DirBuster list - directory-list-2.3-medium.txt
#
#   Copyright 2007 James Fisher
#
#   This work is licensed under the Creative Commons 
#   Attribution-Share Alike 3.0 License. To view a copy of this 
#   license, visit http://creativecommons.org/licenses/by-sa/3.0/ 
#   or send a letter to Creative Commons, 171 Second Street, 
#   Suite 300, San Francisco, California, 94105, USA.
#

#TODO:
    
    # Change number of threads on responce time from server.
    # Fix error reporting for connection issues.
    # Add Pause/Stop/Start functions to script.
    # Add XML output option.
    # Custom 404 page option.
    # Add NTLM Authentication

__author__ = '@NoobieDog'

from sys import argv
import argparse
import Queue
import sys
import threading
import requesocks
import re
import time


def display_message(message):
    global VERBOSE_MODE

    if VERBOSE_MODE:
        print message

class ThreadUrl(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        global results
        while True:
            try:
                folder = self.queue.get().rstrip()
                resource = host + '/' + folder
                try: 
                    if auth_defined:
                        url = requesocks.get(resource, auth=(auth_user, auth_password), headers=headers)
                    elif proxy_defined:
                        url = requesocks.get(resource, proxies=Proxies, headers=headers)
                    elif auth_defined and proxy_defined:
                        url = requesocks.get(resource, proxies=proxy_address, auth=(auth_user, auth_password), headers=headers)
                    elif cookies_defined:
                        url = requesocks.get(resource, cookies=cookies, headers=headers)
                    else:
                        url = requesocks.get(resource, headers=headers)
                    
                    code = url.status_code
                    if (url.status_code not in [200, 401, 403, 404]):
                        results['others'].append(folder)
                    else:
                        display_message("[%s] %s/%s" % (url.status_code, host, folder)) 
                        results[url.status_code].append(folder)
                        
                except requesocks.ConnectionError, e:
                    print R + "\n ERROR: Connection Error - Check host is correct or exists" + W
                    sys.exit()
                self.queue.task_done()
            except (SystemExit): # Shutdown
                pass
                                                        # Console colors
W  = '\033[0m'                                          # white (normal)
R  = '\033[31m'                                         # red
G  = '\033[32m'                                         # green
O  = '\033[33m'                                         # orange
B  = '\033[34m'                                         # blue
GR = '\033[37m'                                         # gray
BB = '\033[1m'                                          # Bold
NB = '\033[0m'                                          # Not bold

if __name__ == '__main__':

    parser = argparse.ArgumentParser( 
                    description='A Python version of DirBuster',
                    epilog='Dir-Xcan is a multi threaded python application designed to brute force directories on web/application servers.')

    parser.add_argument('-s', action="store", help='Website Domain or IP')
    parser.add_argument('-d', action="store", help='Directory word list', default="directorylist.txt")
    parser.add_argument('-n', action="store", help='Number of threads', default="5")
    parser.add_argument('-p', action="store", help='Proxy address and port (host:port)')
    parser.add_argument('-a', action="store", help='Authentication BasicHTTP(username:password)')
    parser.add_argument('-c', action="store", help='use a previously established sessions cookie', default=None)
    parser.add_argument('-u', action="store", help='User-Agent', default="Mozilla/5.0")
    parser.add_argument("-v", action="store_true", help="verbose mode", default=False)

    try:
        args = vars(parser.parse_args())

    except IOError, msg:
        parser.error(str(msg))

        
    print O + '''
     %s _____ _____ _____     __   _______          _   _ 
     |  __ \_   _|  __ \    \ \ / / ____|   /\   | \ | |
     | |  | || | | |__) |____\ V / |       /  \  |  \| |
     | |  | || | |  _  /______> <| |      / /\ \ | . ` |
     | |__| || |_| | \ \     / . \ |____ / ____ \| |\  |
     |_____/_____|_|  \_\   /_/ \_\_____/_/    \_\_| \_|%s
                                                        
     %sRelease Date%s: 06/10/2014
     %sRelease Version%s: V.5.0
     %sCode%s: stuart@sensepost.com // @NoobieDog
     %sVisit%s:  www.sensepost.com // @sensepost
    ''' %(BB,NB,R,W,R,W,R,W,R,W)

    proxy_defined = False
    auth_defined = False
    cookies_defined = False
    VERBOSE_MODE = False
    results = {200: [], 401: [], 403: [], 404: [], 'others': []}

    if not args['s'] or not args['d']:
        parser.print_help()
        sys.exit(-1)
    else:
        # host checking
        host = args['s']
        if not host.startswith("http"):
            print R + ' Please include the http:// or https:// parts' + W
            sys.exit(-1)

        list_file = args['d']
        thread_number = int(args['n'])

        # Verbose mode
        VERBOSE_MODE = args['v']

        # proxy configuration
        proxy_address = args['p']
        if args['p']:
            proxy_defined = True
            Proxies = {
                "http": proxy_address,
                "https": proxy_address
            }

        # authentication configuration
        if args['a']:
            auth_defined = True
            auth_user, auth_password = args['a'].split(':', 1)
        
        # User-Agent configuration
        if args['u']:
            headers = {
                'User-Agent': args['u'],
            }

        # Cookie configuration
        if args['c'] is not None:
            cookies_defined = True
            cookies = {}
            
            # Check to see if the cookie has a semicolon, if so there might be mutiple cookies
            if re.search(';', args['c']):
                print args['c']
                cookie_list = args['c'].split(';')
                # Loop through list of cookies
                for authcookies in cookie_list:

                    # If there isn't an equal and some sort of content, then it isn't a valid cookie, otherwise add to list of cookies
                    if re.search('[":_-/a-zA-Z0-9]', authcookies) and re.search('[=]', authcookies): ##### Error here too, regex all fucked up
                        cookieparts = authcookies.split('=')
                        cookies[cookieparts[0]] = cookieparts[1]

                    else:
                        # Check to see if cookie has =, if not it is malformed and send dummy cookie
                        # If so, split at the = into correct name/value pairs
                        if re.search('=', args['c']):
                            cookie_list = args['c'].split('=')
                            cookies[cookie_list[0]] = cookie_list[1]
                        else:
                            print ' Error in Cookie - Sort your shit out!'
            else:
                cookie_list = args['c'].split('=')
                cookies = {cookie_list[0]: cookie_list[1],}


    with open(list_file) as f:
        directories = f.readlines()
    queue = Queue.Queue()

    start = time.time()
    for i in range(thread_number):
        t = ThreadUrl(queue)
        t.setDaemon(True)
        t.start()

    for directory in directories:
        queue.put(directory)

    try:
        queue.join()
    except (KeyboardInterrupt, SystemExit):
        print R + '\n Ctrl+C Detected! ' + W + '....' + R + '\n Shutting down! ' + W + '....'
        sys.exit()
    print O + '\n Elapsed Time: \033[0m%s' % (time.time() - start)