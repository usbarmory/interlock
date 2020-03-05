Introduction
============

INTERLOCK | https://github.com/f-secure-foundry/interlock  
Copyright (c) F-Secure Corporation

The INTERLOCK application is a file encryption front-end developed, but not
limited to, usage with the [USB armory](https://github.com/f-secure-foundry/usbarmory).

The primary interface consists of a web-based file manager for an encrypted
partition running on the device hosting the JSON application server (e.g. USB
armory).

The file manager allows uploading/downloading of files to/from the encrypted
partition, as well as symmetric/asymmetric cryptographic operations on the
individual files.

![INTERLOCK screenshot](https://github.com/f-secure-foundry/interlock/wiki/images/interlock.png)

A command line mode is available to execute selected operations locally,
without the web interface. This is primarily intended to aid
encryption/decryption operation with hardware keys, using HSM support on
embedded firmwares.

Authors
=======

Andrea Barisani <andrea.barisani@f-secure.com>  
Daniele Bianco  <daniele.bianco@f-secure.com>  

Documentation
=============

The main documentation is included in the present
[file](https://github.com/f-secure-foundry/interlock/blob/master/README.md),
additional information can be found on the
[project wiki](https://github.com/f-secure-foundry/interlock/wiki).

Binary Releases
===============

Pre-compiled binary releases for ARM targets are available
[here](https://github.com/f-secure-foundry/interlock/releases).

Architecture
============

The package provides a web application (client-side) and its counterpart JSON
application server implementing the protocol specified in the API document.

A command line mode is available to execute selected operations locally,
without the web interface. This is primarily intended to aid
encryption/decryption operation with hardware keys, using HSM support on
embedded firmwares.

The JSON application server is written in golang. The client HTML/Javascript
application is statically served by the application server, implementing the
presentation layer.

The interaction between the static HTML/Javascript and the JSON application
server is entirely documented in the API document.

The web application authentication is directly tied to Linux Unified Key Setup
(LUKS) disk-encryption setup on the server side. A successful login unlocks the
specified encrypted volume, while logging out locks it back.

Design goals:

* Clear separation between presentation and server layer to ease auditability
  and integration.

* Minimum amount of external dependencies, currently no code outside of Go
  standard and supplementary libraries is required for the basic server binary.

* Authentication process directly tied to LUKS partition locking/unlocking.

* Support for additional symmetric/asymmetric encryption on individual
  files/directories.

* Minimize exposure of sensitive data to the client with support for disposable
  authentication passwords, server-side operations (key generation,
  encryption/decryption, archive creation/extraction) and locking of private
  keys.

* Minimal footprint (single statically linked binary + supporting static files)
  to ease integration/execution on the USB armory platform.

Ciphers
=======

Encrypted volumes:

* LUKS encrypted partitions

Asymmetric ciphers:

* OpenPGP (using golang.org/x/crypto/openpgp)

Symmetric ciphers:

* AES-256-OFB w/ PBKDF2 password derivation (SHA256, 4096 rounds) and HMAC (SHA256)

Security tokens:

* Time-based One-Time Password Algorithm (TOTP), RFC623 implementation (Google Authenticator)

Hardware Security Modules
=========================

The HSM support allows symmetric ciphering using device specific secret keys,
allowing to uniquely tie derived keys to the specific hardware unit being used.
An HSM specific AES-OFB based symmetric cipher is exposed, with keys derived
from the user password as well as device specific secret.

Additionally the LUKS password, for accessing encrypted volumes, can filtered
through the HSM to make it device specific.

Finally the TLS certificates can also be stored encrypted for a specific
device.

Supported drivers:

* NXP Security Controller (SCCv2)

* NXP Cryptographic Acceleration and Assurance Module (CAAM)

* NXP Data Co-Processor (DCP)

Key Storage
===========

A pre-defined directory, stored on the encrypted filesystem, is assigned to
public and private key storage (see the _Configuration_ section for related
settings).

The keys can be uploaded using the file manager, imported as free text or
generated server-side.

The key storage directory structure is the following:

```
<key_path>/<cipher_name>/<private|public>/<key_identifier>.<key_format>
```

Once uploaded in their respective directory, private keys can only be deleted
or overwritten, they cannot be downloaded, moved or copied.

The keys for OTP ciphers (e.g. "TOTP" implementing Google Authenticator)
generate a valid OTP code, for the current time, when the key information is
queried ('Key Info' action on the right click menu).

Requirements & Operation
========================

The use of INTERLOCK is coupled with the presence of at least one LUKS
encrypted partition, its initial creation is left to the user.

An example setup using cryptsetup and LVM2 follows. The example uses a microSD
partition to illustrate typical USB armory setup, the partition (mmcblk0p2) is
assumed to have been previously created with fdisk using the desired size and
the Linux LVM type (8e).

```
pvcreate /dev/mmcblk0p2                   # initialize physical volume
vgcreate lvmvolume /dev/mmcblk0p2         # create volume group
lvcreate -L 20G -n encryptedfs lvmvolume  # create logical volume of 20 GB

cryptsetup -y --cipher aes-xts-plain64  \ # set-up encrypted partition
  --key-size 256 --hash sha1 luksFormat \ # with default cryptsetup
  /dev/lvmvolume/encryptedfs              # settings

cryptsetup luksOpen /dev/lvmvolume/encryptedfs interlockfs
mkfs.ext4 /dev/mapper/interlockfs         # create ext4 filesystem
cryptsetup luksClose interlockfs
```

The login procedure of INTERLOCK prompts for an encrypted volume name (e.g.
encryptedfs in the previous example) and one valid password for luksOpen.

A successful login unlocks the encrypted partition, a successful logout locks
it back.

Once logged in users can change, add, remove LUKS passwords within INTERLOCK.
Any login password can be disposed of using a dedicated flag during login, this
deletes the password from its LUKS key slot right after encrypted partition
unlocking.

**WARNING**: removing the last remaining password makes the LUKS encrypted
container permanently inaccessible. This is a feature, not a bug.

The following sudo configuration (meant to be included in /etc/sudoers)
illustrates the permission requirements for the user running the INTERLOCK
server. The example assumes username `interlock` with home directory
`/home/interlock` and `volume_group` set to its default (`lvmvolume`).

```
interlock ALL=(root) NOPASSWD:							\
	/bin/date -s @*,							\
	/sbin/poweroff,								\
	/bin/mount /dev/mapper/interlockfs /home/interlock/.interlock-mnt,	\
	/bin/umount /home/interlock/.interlock-mnt,				\
	/bin/chown interlock /home/interlock/.interlock-mnt,			\
	/sbin/cryptsetup luksOpen /dev/lvmvolume/* interlockfs,			\
	!/sbin/cryptsetup luksOpen /dev/lvmvolume/*.* *,			\
	/sbin/cryptsetup luksClose /dev/mapper/interlockfs,			\
	!/sbin/cryptsetup luksClose /dev/mapper/*.*,				\
	/sbin/cryptsetup luksChangeKey /dev/lvmvolume/*,			\
	!/sbin/cryptsetup luksChangeKey /dev/lvmvolume/*.*,			\
	/sbin/cryptsetup luksRemoveKey /dev/lvmvolume/*,			\
	!/sbin/cryptsetup luksRemoveKey /dev/lvmvolume/*.*,			\
	/sbin/cryptsetup luksAddKey /dev/lvmvolume/*,				\
	!/sbin/cryptsetup luksAddKey /dev/lvmvolume/*.*
```

Compiling
=========

The INTERLOCK app requires a working Go (>= 1.4.2) environment to be compiled,
or cross-compiled, under Linux (it is not supported by or designed for other
OSes at this time).

```
git clone https://github.com/f-secure-foundry/interlock
cd interlock
git submodule init
git submodule update
make
```

This compiles the `interlock` binary that can be executed with options
illustrated in the next section.

Alternatively you can automatically download, compile and install the package,
under your GOPATH, as follows:

```
go get github.com/f-secure-foundry/interlock
```

When cross compiling from a non-arm host for an arm target ensure that the
following compilation variables are set:

```
make GOARCH=arm \
     CC=<path_to_cross_compiler>/arm-linux-gnueabihf-gcc \
     CGO_ENABLED=1
```

Options
=======

```
  -h                   options help
  -b="0.0.0.0:4430"    binding address:port pair
  -c="interlock.conf"  configuration file path
  -o=""                operation ((open:<volume>)|close|derive(:<data>)?)
  -d=false:            debug mode
  -t=false:            test mode (WARNING: disables authentication)
```

The operation flag allows selected actions to be performed locally, without a
web interface. The following operations are supported:

* `open:<volume>`:  unlock LUKS volume to mapping "interlockfs", prompts
                    password once. Uses HSM key derivation when configured.

* `close`:          lock the LUKS volume mapped to "interlockfs".

* `derive:<data>`:  HSM key derivation from data (e.g. diversifier) specified
                    in hex format (e.g. `derive:12ef`).

* `derive`:         HSM key derivation from password, prompted twice
                    interactively.

Configuration
=============

* `debug`:         enable debugging logs.

* `static_path`:   directory path for INTERLOCK static HTML/JavaScript files
                   ("static" directory included in project repository).

* `set_time`:      use the client browser time to set server time at login,
                   useful on non-routed USB armory devices (unable to set the
                   clock on their own).

* `bind_address`:  IP address, port pair.

* `tls`:

  - `on`:          use `tls_cert` and `tls_key` paths as HTTPS TLS keypair;

  - `gen`:         generate a new TLS keypair and save it to `tls_cert` and
                   `tls_key` paths when pointing to non existent files
                   (otherwise behaves like "on"), useful for testing and TOFU
                   (Trust On First Use) schemes;

  - `off`:         disable HTTPS.

*      `tls_cert`: HTTPS server TLS certificate.

*       `tls_key`: HTTPS server TLS key.

* `tls_client_ca`: optional CA for HTTPS client authentication, client
                   certificate requires TLS Web Client Authentication X509v3
                   Extended Key Usage extension to be correctly validated.

* `hsm`:

  - `<model>:<options>`: enable <model> HSM support with <options>, multiple
                         options can be combined in a comma separated list
                         (e.g. `"mxc-scc2:luks,tls,cipher"`);

  - `off`:               disable HSM support.

  Available modules:

  - `mxc-scc2`:          NXP Security Controller (SCCv2). Requires kernel driver
                         [mxc-scc2](https://github.com/f-secure-foundry/mxc-scc2).

  - `caam-keyblob`:      NXP Cryptographic Acceleration and Assurance Module (CAAM).
                         *NOTE*: stores encrypted derived keys in `~/.luks_kb/`,
                         which must be accompanied to the LUKS partition itself
                         when creating data backups. Requires kernel driver
                         [caam-keyblob](https://github.com/f-secure-foundry/caam-keyblob).

  - `mxs-dcp`:           NXP Data Co-Processor (DCP). Requires kernel driver
                         [mxs-dcp](https://github.com/f-secure-foundry/mxs-dcp).

  Available options:

  - `luks`:              use HSM secret key to AES encrypt LUKS passwords and
                         make them device specific before use; LUKS login and
                         password operations (add, change, remove) fallback, in
                         case of failure, to plain ones in order to allow
                         change of credentials on pre-HSM deployments;

  - `tls`:               use HSM secret key to AES-256-OFB encrypt the HTTPS
                         server TLS key (tls_key), automatically convert
                         existing plaintext keys;

  - `cipher`:            expose AES-256-OFB derived symmetric cipher with
                         password key derivation through HSM encryption to make
                         it device specific.

* `key_path`:     path for public/private key storage on the encrypted
                  filesystem.

* `volume_group`: volume group name.

* `ciphers`:      array of cipher names to enable, supported values are
                  ["OpenPGP", "AES-256-OFB", "TOTP"].

The following example illustrates the configuration file format (plain JSON)
and its default values.

```
{
        "debug": false,
        "static_path": "static",
        "set_time": false,
        "bind_address": "0.0.0.0:4430",
        "tls": "on",
        "tls_cert": "certs/cert.pem",
        "tls_key": "certs/key.pem",
        "tls_client_ca": "",
        "hsm": "off",
        "key_path": "keys",
        "volume_group": "lvmvolume"
        "ciphers": [
                "OpenPGP",
                "AES-256-OFB",
                "TOTP"
        ]
}

```

At startup the interlock server dumps the applied configuration in its file
format.

Logging
=======

The application generates debug, audit, notification and error logs.

Debugging logs are only generated when "debug" is set to true in the
configuration file (or command line switch). In debug mode all logs are printed
on standard output and never saved.

Audit and error logs are shown live in a dedicated area on the web client
('Application logs') and saved on the root directory of the encrypted partition
in the `.interlock.log` file.

Notifications are shown live in a dedicated area on the web client ('Current
activity'), they are only kept in memory in a circular buffer and never stored
on disk.

Any non-debug log generated outside an unauthenticated session is issued
through standard syslog facility.

License
=======

INTERLOCK | https://github.com/f-secure-foundry/interlock  
Copyright (c) F-Secure Corporation

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation under version 3 of the License.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

See accompanying LICENSE file for full details.
