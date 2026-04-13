# Find Hub Network Beacon Tools

This repository contains a collection of tools for working with locator tags
and other beacon hardware compatible with Google's Find Hub Network. These
tools allow you to provision a new (or previously factory reset) beacon so it
will start sending periodic Bluetooth advertisements. As part of the
provisioning process, the tool generates and installs a cryptographic key on
the beacon. As long as you remember that key, you can associate future
Bluetooth advertisements with that particular beacon, even though its MAC
address changes randomly. Another tool is provided to perform this tracking.

Note that the tools here communicate _only_ with the beacon hardware over
Bluetooth. They do _not_ make any API calls to Google. Beacons provisioned
using this tool are not associated with a Google account, so you will not be
able to query the Find Hub Network for their location. Specifically, you will
only be able to track these beacons if they are in range of a Bluetooth adapter
you control. (Note that the tracking tool here _can_ work with beacons that
were provisioned by Google and are part of the Find Hub Network, if you have
some way to acquire the relevant key material.)

This limitation may be acceptable for certain use cases, such as when tracking
objects that rarely/never leave the building (like pets or tools), or if you
are only interested in knowing the home/away status of an object or knowing if
it is inside a particular area. For these use cases, Find Hub Network beacons
provide an upgrade over Eddystone or other simple Bluetooth beacons, as the
hardware is generally very small, lightweight, and water resistant, with good
battery life, and the protocol provides meaningful privacy enhancements.

The advantages of local provisioning are that it works offline, and that it
gives you complete control over the cryptographic keys needed to track and
control the beacon. You can track the beacon from any device, not just an
Android phone, allowing integration with projects like [ESPresence] and [Home
Assistant] ([Bermuda]).

[ESPresence]: https://espresense.com/
[Home Assistant]: https://www.home-assistant.io/integrations/device_tracker/
[Bermuda]: https://github.com/agittins/bermuda

## Usage

### Acquiring the anti-spoofing public key

While the tools here do not perform any network communication or API calls, one
piece of information from Google may be required to provision your device.
Specifically, each _model_ of Find Hub Network certified device is allocated a
public/private "anti-spoofing" key pair. The private key is stored on each
beacon, and the public key is provided by Google to the (normally) Android
device trying to pair with it, based on a 24-bit model ID advertised by the
beacon when it is in pairing mode.

The provisioning tool contains a table of known model IDs and public keys
already, so if your device is already included in this table, you can skip this
step. Otherwise, you will need to acquire the public key from Google. Since
Google does not provide a public API to retrieve these keys, the method
described here requires a rooted Android device with Google Play Services and
an Internet connection. It does _not_ require a Google Account. And if you have
multiple beacons of the same model, you only need to do this once per model.

1) Enable Bluetooth on your Android device.
2) Go to Settings > Google > All services > Devices and ensure "Scan for nearby
   devices" is enabled.
3) Turn on your beacon.
4) Wait for the "half-sheet" pairing prompt to appear on your Android device.
   It will contain the model name and a picture of your beacon. See Google's
   [FAQ] if the notification does not appear.
5) You do not need to pair the beacon with the Android device! Just dismiss
   the notification.
6) Use ADB or a file browser with root access to copy the following directory
   to your computer:

```
/data/data/com.google.android.gms/files/nearby-fast-pair/nearby_scan_fast_pair_item_cache.db
```

7) Run `extract_anti_spoofing_key.py` and pass it the path to the database:

```
python3 extract_anti_spoofing_key.py path/to/nearby_scan_fast_pair_item_cache.db
```

8) Finally, add the lines output from this script to the
`KNOWN_ANTI_SPOOFING_PUBLIC_KEYS` dictionary in `fhn_provision.py`.

If `extract_anti_spoofing_key.py` fails to parse the database, you can use a
LevelDB viewer to open the database and find the entry corresponding to the
24-bit ID in your beacon's Bluetooth advertisement. The database entry value is
a protobuf blob. Pipe that into `protoc --decode_raw` or an online decoder, and
look for a 64-byte binary value near the beginning.

[FAQ]: https://developers.google.cn/nearby/fast-pair/fast-pair-faq#half-sheet

### Pairing and provisioning a beacon

Run `fhn_provision.py` and turn on your beacon. This will pair with any
unpaired Fast Pair devices seen in the next 10 seconds. If the device is also a
Find Hub Network beacon, it will provision the Ephemeral Identity Key, which is
used to generate the periodic beacon advertisements. **Save the output of this
script!** If you lose the keys, you will need to factory reset your beacon.

* The Account Key is used to configure, reprovision, or unpair the beacon.
* The Ephemeral Identity Key, EID curve, and clock offset are all needed to
  track the beacon.

The output should look something like this:
```
D4:70:8D:B4:3D:2B | Discovered new device
D4:70:8D:B4:3D:2B | Shared Secret: 99a0ec856bf15d4de5076ff377ff96b4
D4:70:8D:B4:3D:2B | Account Key: 04cc19257230358cf76051fc3efa31a2
D4:70:8D:B4:3D:2B | Ephemeral Identity Key: c8a70db70e4560a7861d6bd72cce69fb6b3fc62e05f2d03203590b140b37fd19
D4:70:8D:B4:3D:2B | Connecting...
D4:70:8D:B4:3D:2B | Starting key-based pairing...
D4:70:8D:B4:3D:2B | Writing key-based pairing request...
D4:70:8D:B4:3D:2B | Got key-based pairing response...
D4:70:8D:B4:3D:2B | Provider's public BR/EDR address: d4:70:8d:b4:3d:2b
D4:70:8D:B4:3D:2B | Writing account key...
D4:70:8D:B4:3D:2B | Provisioning Find Hub Network beacon...
D4:70:8D:B4:3D:2B | Clock offset: 26044551 (value=1749899900)
D4:70:8D:B4:3D:2B | EID curve: secp160r1
D4:70:8D:B4:3D:2B | Setting ephemeral identity key...
D4:70:8D:B4:3D:2B | Done!
```

### Tracking a beacon

Update the `KNOWN_FHN_BEACONS` list in `fhn_track.py` with an entry for each
provisioned beacon, consisting of:

* The clock offset reported when provisioning
* The EID curve reported when provisioning
* The Ephemeral Identity Key reported when provisioning
* Any name you want to use to identify the tracker

Note that the clock offset can change if the beacon loses power (by removing
the battery). A "Read beacon parameters" request can be used to compute a new
clock offset, but this is not currently implemented.

The Find Hub Network Accessory Specification handles clock drift by computing
Ephemeral IDs (EIDs) for times in the near past and near future, in addition to
the "expected" EID. A tracker should update the clock offset if a beacon is
advertising an EID that is ahead or behind, but this is also not implemented.

`fhn_track.py` will run continuously and output lines of the form:

```
2026-04-12 15:45:56.555548: 70:86:FB:55:DD:DA (RSSI  -97): 408ec764325c3e2e4c094aba9b5232f123fc6bbb2c2d: example beacon
```

which is the timestamp, MAC address, RSSI, service data from the advertisement,
and the user-assigned beacon name.

## Specifications

These tools implement the Seeker role of the Google Fast Pair Service and the
Find Hub Network Accessory Specification, which are available here:
 * https://developers.google.com/nearby/fast-pair/specifications/introduction
 * https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn
