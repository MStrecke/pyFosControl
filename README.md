pyFosControl
============

Python interface to Foscam CGI API for HD models

Introduction
------------

The Foscam cameras can be controlled via a web interface.  There are browser plugins available for Firefox,
Chrome and IE, which are bundled with the camera firmware and can be downloaded using the cameras web interface.

However, these plugins are Windows only.  Without them only a few basic configuration options are available (network,
user accounts, firewall, etc.).  The bulk of the functionality including the display of the camera pictures,
controlling the ptz movements, motion detection, are not available on a Linux computer.

There is a [SDK](http://foscam.us/forum/cgi-sdk-for-hd-camera-t6045.html#p28979 "SDK for HD cameras") available
describing a CGI interface which seems to make most of these functions available. pyFosControl is intended as an
python interface.

At the moment it is a simple python file which can be imported by a program in the same directory.  After it becomes
more complete, I will turn it into a regular library.

Getting started
---------------

Create a new `cam.cfg` file using `cam.cfg.example` as template.

Run `pyFosControl.py` from the command line to get some basic information (like model info, firmware and hardware version).

Please note
-----------

* This interface is far from complete.
* It's *mostly* tested on a FI9821W V2.
* The SDK documentation is inaccurate in places.
* The non HD cameras use a different set of CGI commands and are not covered in this implementation.
* The behaviour of the camera changes slightly with each new firmware version.  Please include model and firmware version
  when sending bug reports (run pyFosControl.py from the command line.

