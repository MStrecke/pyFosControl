# Low level protocol for Foscam FI9821W V2

## Introduction

The Foscam FI9821W V2 is a HD H.264 camera which can be remote controlled via a TCP/IP connection.

Usually a browser based extension is used to access the camera.  However this extension only works on Windows.
Without it only the basic configuration is accessible.

The plugin uses two protocols to control the camera.

 * A *CGI based commands* which are described [here](http://foscam.us/forum/cgi-sdk-for-hd-camera-t6045.html#p28979).
 * A *low level protocol* which has not yet been published (as of the time of writing).

Most functions of the browser plugin are available via the CGI commands.  In fact, the browser plugin does use it as well.

There are some functions however that are only available via the low level protocol, e.g. sending audio to the camera.

## Basics

**Note:** All information presented in this document have been gleaned by analysing the network traffic from
 and to the camera.  There is no guarantee that my assumptions are correct.

For identification three pieces of data are used:
 * username
 * password
 * UID - a random 32 bit value, which does not changed during a session.  You can use the Unix timestamp for example.

To use the low level protocol connect to port 88 or 443 (or presumably any other port you have configured) via TCP.

**Note:** This communication is **not** encrypted.

The camera will close an idle connection after 60 secs. (I.e. use command 15 for a Noop action).

### Start

In order to start the communication send the following HTTP 1.1 request to the camera:

 * Change the *Host* header accordingly.
 * Keep in mind to use CR LF between the lines.


```
SERVERPUSH / HTTP/1.1
Host: 192.168.0.22:88
Accept:*/*
Connection: Close


```

### Packet format

 * All integers are little endian.

```
Int32   command #
char4   magic number: FOSC
Int32   size of data block
... data block ...
```

### Command seen so far
### User -> Camera

| Hex | Dec | Description          |
| --: | --: | -------------------- |
| 00  |   0 | video on             |
| 01  |   1 | close connection     |
| 02  |   2 | audio on (from cam)  |
| 03  |   3 | audio off (from cam) |
| 04  |   4 | speaker on cmd       |
| 05  |   5 | speaker off cmd      |
| 06  |   6 | talk audio data      |
| 0c  |  12 | Login                |
| 0f  |  15 | Login check          |

N+P: name and password
N+P+U: name, password, and UID
nc: not checked

### Camera -> User

| Hex | Dec | Description                         |
| --: | --: | ----------------------------------- |
| 10  |  16 | ???                                 |
| 12  |  18 | ???                                 |
| 14  |  20 | speaker on reply                    |
| 15  |  21 | speaker off reply                   |
| 1a  |  26 | video data in                       |
| 1b  |  27 | audio data in                       |
| 1d  |  29 | Login check reply                   |
| 64  | 100 | ptz info                            |
| 6C  | 108 | show mirror/flip                    |
| 6E  | 110 | show color adjust values            |
| 6F  | 111 | Motion detection alert              |
| 70  | 112 | show power freq: 50/60/outdoor mode |
| 71  | 113 | stream select reply                 |

# Description of the commands


All commands start with the following header.

| type  | value | description            |
| ----- | ----: | ---------------------- |
| int32 | X     | command number         |
| char4 | FOSC  | magic number           |
| int32 | X     | size of the data block |

The following part only describes the data section.

 * *Integers* are little endian.
 * *Character strings* are padded with zeros.
 * *Reserved* means: no idea

**Type column**

| type  | meaning                        |
| ----- | ------------------------------ |
| int32 | 32 bit integer, little endian  |
| byte  | byte, 8 bit                    |
| charX | character string, X **bytes**  |
| resX  | unknown data, X **bytes**      |

**Value column**

| value | meaning                                     |
| ----: | ------------------------------------------- |
|     0 | zero, zeroes (in case of strings)           |
|     X | specific meaning detailed under description |
|     ? | unknown non-zero values                     |

## Packet 0 - Video on

| type   | value | description                 |
| ------ | ----: | --------------------------- |
| byte   |     0 | videostream (0:main, 1:sub) |
| char64 |     X | username                    |
| char64 |     X | password                    |
| int32  |     X | UID                         |
| res28  |     0 | ?                           |

## Packet 1 - close connection

| type   | value | description            |
| ------ | ----: | ---------------------- |
| byte   |     0 | ?                      |
| char64 |     X | username               |
| char64 |     X | password               |

Closes the socket.  You have to establish a new connection and start with **SERVERPUSH**.


## Packet 2 - Audio on (from cam)

| type   | value | description            |
| ------ | ----: | ---------------------- |
| byte   |     0 | ?                      |
| char64 |     X | username               |
| char64 |     X | password               |
| res32  |     0 | ?                      |

Camera starts to send audio in command 27 packets.
Format: Raw, 8000 Hz, Signed 16 Bit PCM, Mono, Little Endian

## Packet 3 - Audio off (from cam)

| type   | value | description            |
| ------ | ----: | ---------------------- |
| byte   |     0 | ?                      |
| char64 |     X | username               |
| char64 |     X | password               |
| res32  |     0 | ?                      |


## Packet 4 - Speaker on

| type   | value | description            |
| ------ | ----: | ---------------------- |
| byte   |     0 | ?                      |
| char64 |     X | username               |
| char64 |     X | password               |
| int32  |     X | UID                    |
| res28  |     0 | ?                      |

Informs the camera that talk data will follow.
The camera acknowledges with command 20.
Talk data will then be sent with command 6.

## Packet 5 - Speaker off

| type   | value | description            |
| ------ | ----: | ---------------------- |
| byte   |     0 | ?                      |
| char64 |     X | username               |
| char64 |     X | password               |
| res32  |     0 | ?                      |

Switches the camera speaker off.
The camera acknowledges with command 21.

## Packet 6 - Talk data

| type   | value | description            |
| ------ | ----: | ---------------------- |
| int32  |     X | audiolen               |
| binary |     ? | audio data             |

The captured data suggests that the binary data blog must <= 960 bytes.
I'm not about the audio format.  I presume: Raw 8000 Hz, 16 bit
However, dumping a converted file to the camera with raw audio data did not work.
It seems that there is little to no buffering in the camera before the data is sent
to the loudspeaker.

## Packet 12 - Login

| type   | value | description            |
| ------ | ----: | ---------------------- |
| byte   |     0 | ?                      |
| char64 |     X | username               |
| char64 |     X | password               |
| int32  |     X | UID                    |
| res32  |     0 | ?                      |

This is usually the first command which is sent to the camera.
The camera responds with packet 100 containing various information (points, cruises, etc.)
If the login fails the camera still answers with packet 100, however with no data inside.

Note: This command is 4 bytes longer than similar commands.

## Packet 15 - Login check

| type   | value | description            |
| ------ | ----: | ---------------------- |
| int32  |     X | UID                    |

This command is used to check if a login is (still) valid.
The camera answers with command 29.

It is usually the first command after Login (command 12) to check if Login was successful.
However, in the captured data the plugin sends this command in regular intervals.


## Packet 16 - Unknown

36 bytes with look similar (but not identical to reply 18).

## Packet 18 - Unknown

36 bytes with look similar (but not identical to reply 16).

## Packet 20 - Speaker on reply

This packet is sent from the camera in reply to command 4.
36 bytes with resemblance to reply 21, 16 and 18.
No idea what they mean,

## Packet 21 - Speaker off reply

This packet is sent from the camera in reply to command 5.
36 bytes with resemblance to reply 20, 16 and 18.
No idea what they mean,

## Packet 26 - Video data in

No idea.

## Packet 27 - Audio data in

| type   | value | description            |
| ------ | ----: | ---------------------- |
| int32  |     X | audio data size        |
| binary |       | audio data content     |

The *audio data size* is usually the *size of datablock* in the header minus 4.

If you dump the audio data content into a file, you get a raw, 8000 Hz, signed 16 bit integer audio file.

## Packet 29 - Login reply

| type   | value | description               |
| ------ | ----: | ------------------------- |
| int32  | 0 / 1 | login ok = 0 / failed = 1 |

Reply to packet 15 (login check)-


## Packet 100 ptz info

The camera sends this packet after receiving command 0.  It contains the preset points, cruises, and some other information

| type       | value | description              |
| ---------- | ----: | ------------------------ |
| char8      |     0 | ?? all zeros             |
| byte       |     X | number of preset points  |
| 16* char32 |     X | name of the preset point |
| res32      |     0 | ? all zeros              |
| byte       |     X | number of cruises        |
| 8* char32  |     X | name of the cruise       |
| res32      |     0 | ? all zeros              |
| res92      |     ? | ?                        |
| char12     |     X | camera id                |
| ...        |     ? | ?                        |

FYI: The *web interface* imposes the following restrictions:
 * max. name length of preset point: 20 chars
 * max. number of preset points: 16
 * max. name length of cruise: 20 chars
 * max. number of cruises: 8
 * max. number of preset points per cruise: 8

## Packet 108 - Show mirror/flip

| type   | value | description             |
| ------ | ----: | ----------------------- |
| int32  | 0 / 1 | mirror 0 = no / 1 = yes |
| int32  | 0 / 1 | flip 0 = no / 1 = yes   |

This packet is sent when the user changes the settings via the CGI commamnds.

## Packet 110 - Show color adjustments values

| type   | value | description             |
| ------ | ----: | ----------------------- |
| byte   |     X | brightness              |
| byte   |     X | contrast                |
| byte   |     X | hue                     |
| byte   |     X | saturation              |
| byte   |     X | sharpness               |
| byte   |    50 | not used (denoise?)     |

This packet is sent when the user changes these settings via the CGI commamnds.
Range: 0 .. 100

## Packet 111 - Motion detection alert

| type   | value | description             |
| ------ | ----: | ----------------------- |
| res4   |     ? | 01 00 00 1e             |

This packet only occurs if motion detection is enabled.

## Packet 112 - Show power frequency

| type   | value | description                 |
| ------ | ----: | --------------------------- |
| int32  | 0..2  | 0=60 Hz, 1=50 Hz, 2=outdoor |

This packet is sent when the user changes the setting via the CGI commamnd.

## Packet 113 - Show stream selection

| type   | value | description                 |
| ------ | ----: | --------------------------- |
| int32  |    X  | stream number               |

This packet is sent when the user changes the setting via the CGI commamnd.
