import asyncio
import secrets

from bleak import AdvertisementData, BLEDevice, BleakClient, BleakScanner
from collections import OrderedDict
from collections.abc import Collection
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from fastecdsa.curve import Curve
from fastecdsa.keys import get_public_key
from typing import Optional

EDDYSTONE_SERVICE_UUID = "0000feaa-0000-1000-8000-00805f9b34fb"

ROTATION_PERIOD_EXPONENT = 10
ROTATION_PERIOD = 1 << ROTATION_PERIOD_EXPONENT
ROTATION_PERIOD_DELTA = timedelta(seconds=ROTATION_PERIOD)

SECP160R1 = Curve(
    name="secp160r1",
    p=0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_7FFFFFFF,
    a=0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_7FFFFFFC,
    b=0x1C97BEFC_54BD7A8B_65ACF89F_81D4D4AD_C565FA45,
    q=0x01_00000000_00000000_0001F4C8_F927AED3_CA752257,
    gx=0x4A96B568_8EF57328_46646989_68C38BB9_13CBFC82,
    gy=0x23A62855_3168947D_59DCC912_04235137_7AC5FB32,
    oid=bytes.fromhex("2b81040008"),
)

SECP256R1 = Curve(
    name="secp256r1",
    p=0xFFFFFFFF_00000001_00000000_00000000_00000000_FFFFFFFF_FFFFFFFF_FFFFFFFF,
    a=0xFFFFFFFF_00000001_00000000_00000000_00000000_FFFFFFFF_FFFFFFFF_FFFFFFFC,
    b=0x5AC635D8_AA3A93E7_B3EBBD55_769886BC_651D06B0_CC53B0F6_3BCE3C3E_27D2604B,
    q=0xFFFFFFFF_00000000_FFFFFFFF_FFFFFFFF_BCE6FAAD_A7179E84_F3B9CAC2_FC632551,
    gx=0x6B17D1F2_E12C4247_F8BCE6E5_63A440F2_77037D81_2DEB33A0_F4A13945_D898C296,
    gy=0x4FE342E2_FE1A7F9B_8EE7EB4A_7C0F9E16_2BCE3357_6B315ECE_CBB64068_37BF51F5,
    oid=bytes.fromhex("2a8648ce3d030107"),
)


@dataclass
class FHNBeacon:
    clock_offset: float
    curve: Curve
    ephemeral_identity_key: bytes
    name: str

    def _aes256_encrypt(self, key: bytes, message: bytes):
        encryptor = Cipher(algorithms.AES256(key), modes.ECB()).encryptor()
        return encryptor.update(message) + encryptor.finalize()

    @property
    def eid_length(self):
        return {
            SECP160R1: 20,
            SECP256R1: 32,
        }[self.curve]

    def generate_eid(self, when: datetime) -> bytes:
        clock_value = int(when.timestamp() - self.clock_offset)
        clock_value -= clock_value % ROTATION_PERIOD
        plaintext = bytearray(32)
        plaintext[0:11] = b"\xff" * 11
        plaintext[11] = ROTATION_PERIOD_EXPONENT
        plaintext[12:16] = clock_value.to_bytes(4)
        plaintext[16:27] = b"\x00" * 11
        plaintext[27] = ROTATION_PERIOD_EXPONENT
        plaintext[28:32] = clock_value.to_bytes(4)
        rprime = int.from_bytes(
            self._aes256_encrypt(self.ephemeral_identity_key, plaintext)
        )
        r = rprime % self.curve.q
        R = get_public_key(r, self.curve)
        return R.x.to_bytes(self.eid_length)


MAX_CLOCK_SKEW = timedelta(days=1)
MAX_TRACKED_ROTATIONS = 90


class TrackedFHNBeacon:
    beacon: FHNBeacon
    device: Optional[BLEDevice] = None
    eids: OrderedDict[bytes, datetime]
    last_seen: Optional[datetime] = None

    def __init__(self, beacon: FHNBeacon, now: datetime):
        self.beacon = beacon
        self.eids = {}
        self._generate_eids(now)

    def _generate_eids(self, now: datetime):
        self.eids.clear()
        adv_time = now - MAX_CLOCK_SKEW
        for _ in range(MAX_TRACKED_ROTATIONS):
            self.eids[self.beacon.generate_eid(adv_time)] = adv_time
            adv_time += ROTATION_PERIOD_DELTA

    def match(self, device: BLEDevice, advertisement: bytes, now: datetime) -> bool:
        if len(advertisement) - self.beacon.eid_length not in (1, 2):
            return False
        if advertisement[0] not in (0x40, 0x41):
            return False
        eid = advertisement[1 : 1 + self.beacon.eid_length]
        min_adv_time = now - MAX_CLOCK_SKEW
        for old_eid, adv_time in self.eids.items():
            if adv_time >= min_adv_time:
                break
            del self.eids[old_eid]
            adv_time += timedelta(seconds=MAX_TRACKED_ROTATIONS * ROTATION_PERIOD)
            self.eids[self.beacon.generate_eid(adv_time)] = adv_time
        try:
            adv_time = self.eids[eid]
        except KeyError:
            return False
        # TODO adjust clock offset
        self.device = device
        self.last_seen = now
        return True


class FHNTracker:
    beacons: Collection[TrackedFHNBeacon]

    def __init__(self, beacons: Collection[TrackedFHNBeacon]):
        now = datetime.now()
        self.beacons = [TrackedFHNBeacon(beacon, now) for beacon in beacons]

    def match(self, device: BLEDevice, advertisement_data: AdvertisementData):
        advertisement = advertisement_data.service_data[EDDYSTONE_SERVICE_UUID]
        now = datetime.now()
        for beacon in self.beacons:
            if beacon.match(device, advertisement, now):
                name = beacon.beacon.name
                break
        else:
            name = "(no match)"
        print(
            f"{now}: {device.address} (RSSI {advertisement_data.rssi:4}): {advertisement.hex()}: {name}"
        )


KNOWN_FHN_BEACONS = [
    FHNBeacon(
        26044551,
        SECP160R1,
        bytes.fromhex(
            "c8a70db70e4560a7861d6bd72cce69fb6b3fc62e05f2d03203590b140b37fd19"
        ),
        "example beacon",
    ),
]


async def main():
    tracker = FHNTracker(KNOWN_FHN_BEACONS)

    async with BleakScanner(tracker.match, [EDDYSTONE_SERVICE_UUID]) as scanner:
        try:
            await asyncio.Event().wait()
        except asyncio.exceptions.CancelledError:
            pass


if __name__ == "__main__":
    asyncio.run(main())
