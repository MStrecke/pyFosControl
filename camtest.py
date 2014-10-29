#!/usr/bin/python
# -*- coding: utf-8 -*-

from foscontrol import Cam
import ConfigParser

################################
# Don't forget to edit cam.cfg #
# to reflect you setup!        #
################################

if __name__ == "__main__":
    config = ConfigParser.ConfigParser()

    # see cam.cfg.example
    config.readfp(open('cam.cfg'))
    prot = config.get('general', 'protocol')
    host = config.get('general', 'host')
    port = config.get('general', 'port')
    user = config.get('general', 'user')
    passwd = config.get('general', 'password')

    # connection to the camera
    do = Cam(prot, host, port, user, passwd)

    # display basic camera info
    res = do.getDevInfo()
    if res.result == 0:  # quick check
        print """product name: %s
serial number: %s
camera name: %s
firmware version: %s
hardware version: %s""" % (res.productName, res.serialNo, res.devName, res.firmwareVer, res.hardwareVer)
    else:
        print res._result

