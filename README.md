**NOTE**: code & documentation are of alpha quality at this stage, not for
production use.

Introduction
============

INTERLOCK
Copyright (c) 2015 Inverse Path S.r.l.

The INTERLOCK application is a file encryption front-end developed, but not
limited to, usage with the [USB armory](http://inversepath.com/usbarmory).

The goal of the package is to expose a simple file manager for an encrypted
partition running on the device hosting the JSON application server (i.e. USB
armory).

The file manager allows uploading/downloading of files to/from the encrypted
partition, as well as additional symmetric/asymmetric cryptographic operations
on the individual files.

Architecture
============

The application provides a web application (client-side) and its counterpart
JSON application server implementing the protocol specified in the API
document.

The JSON application server is written in golang. The client HTML/Javascript
application is statically served by the application server, implementing the
presentation layer.

The interaction between the static HTML/Javascript and the JSON application
server is entirely documented in the API document.

The authentication is directly tied to Linux Unified Key Setup (LUKS)
disk-encryption setup on the server side. A successful login unlocks the
specified encrypted volume, while logging out locks it back.

Design goals:

* Clear separation between presentation and server layer to ease auditability
  and integration.

* Authentication process directly tied to LUKS partition locking/unlocking.

* Support for additional symmetric/asymmetric encryption on individual
  files/directories.

* Support for disposable authentication passwords, emergency self destruct
  (LUKS nuke)

* Minimal footprint (single statically linked binary + supporting static files)
  to ease integration with USB armory secure booted initrd ramdisk.

Requirements
============

The use of INTERLOCK is coupled with the presence of a LUKS encrypted
partition, its initial creation (for now) is left as an exercise to the user.

An example setup using cryptsetup and lvm2 follows (microSD partition is shown
to illustrate typical USB armory setup):

```
pvcreate /dev/mmcblk0p2
vgcreate lvmvolume /dev/mmcblk0p2
lvcreate -L 20G -n encryptedfs lvmvolume
cryptsetup -y --cipher aes-xts-plain64 --key-size 256 --hash sha1 luksFormat /dev/lvmvolume/encryptedfs
cryptsetup luksOpen /dev/lvmvolume/encryptedfs interlockfs
mkfs.ext4 /dev/mapper/interlockfs
cryptsetup luksClose interlockfs
```

Compiling
=========

The INTERLOCK app requires a working Go environment to be compiled.

```
go get -u golang.org/x/crypto/pbkdf2
go get -u golang.org/x/crypto/openpgp
make
```

This compiles the 'interlock' binary that can be executed with options
illustrated in the next section.

Options
=======

```
  -h                   options help
  -b="127.0.0.1:443"   binding address:port pair
  -c="interlock.conf"  configuration file path
  -d=false:            debug mode
  -t=false:            test mode (WARNING: disables authentication)
```

Configuration
=============

* debug: enable debugging logs

* set_time: use the client browser time to set server time at login, useful on
  non-routed USB armory devices (unable to set the clock on their own)

* bind_address: IP address, port pair

* tls_cert: HTTPS server TLS certificate

* tls_key: HTTPS server TLS key

* key_path: path for public/private key storage on the encrypted filesystem

* ciphers: array of cipher names to enable

The following example illustrates the configuration file format and setting
defaults.

```
{
        "debug": false,
        "set_time": false,
        "bind_address": "127.0.0.1:4430",
        "tls_cert": "certs/cert.pem",
        "tls_key": "certs/key.pem",
        "key_path": "keys",
        "ciphers": [
                "OpenPGP",
                "AES-256-OFB"
        ]
}

```

At startup the interlock binary dumps the applied configuration in its file
format.

Authors
=======

Andrea Barisani <andrea@inversepath.com>  
Daniele Bianco  <danbia@inversepath.com>  

License
=======

INTERLOCK | https://github.com/inversepath/interlock
Copyright (c) 2015 Inverse Path S.r.l.

Permission to use, copy, modify, and distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright notice
and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
