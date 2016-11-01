#!/usr/bin/python3
# -*- coding: utf-8 -*-

from __future__ import print_function

from foscontrol import Cam
import sys

try:  # PY3
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import SafeConfigParser as ConfigParser

################################
# Don't forget to edit cam.cfg #
# to reflect you setup!        #
################################

if __name__ == "__main__":
    config = ConfigParser()

    # see cam.cfg.example
    config.read(['cam.cfg'])
    prot = config.get('general', 'protocol')
    host = config.get('general', 'host')
    port = config.get('general', 'port')
    user = config.get('general', 'user')
    passwd = config.get('general', 'password')

    if sys.hexversion < 0x03040300:
        # parameter context not available
        ctx = None
    else:
        # disable cert checking
        # see also http://tuxpool.blogspot.de/2016/05/accessing-servers-with-self-signed.html
        import ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    # connection to the camera
    do = Cam(prot, host, port, user, passwd, context=ctx)

    (img, fnm) = do.snapPicture()
    # Possible errors/exceptions:
    #
    # urllib.error.URLError (e.g. no route to host)
    # ssl.CertificateError (e.g. wrong or no ssl certificate)
    # img == None (e.g. wrong password)

    if img is not None:
        print('Writing picture')
        open('/tmp/test.jpg', 'wb').write(img)
    else:
        print('No picture')


