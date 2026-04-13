import asyncio
import secrets
import time

from bleak import (
    AdvertisementData,
    BLEDevice,
    BleakCharacteristicNotFoundError,
    BleakClient,
    BleakGATTCharacteristic,
    BleakScanner,
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from typing import Optional

FAST_PAIR_SERVICE_UUID = "0000fe2c-0000-1000-8000-00805f9b34fb"

KEY_BASED_PAIRING_CHARACTERISTIC = "fe2c1234-8366-4814-8eb0-01de32100bea"
ACCOUNT_KEY_CHARACTERISTIC = "fe2c1236-8366-4814-8eb0-01de32100bea"
BEACON_ACTIONS_CHARACTERISTIC = "fe2c1238-8366-4814-8eb0-01de32100bea"

KNOWN_ANTI_SPOOFING_PUBLIC_KEYS = {
    # Shenzhen Lunci Technology Co., Ltd - OTAG
    0x93cdaa: bytes.fromhex("13b31eabb6f1423b0e72cabd57d08b6045e283bf2c117f98b4f0984bedab924ae277cce0d212bd82a728ab9e631b05c78027e237fcbbd586d5e8e0ba406988fd"),
}


class FastPairHandshake:
    address: str
    public_address: Optional[str] = None
    client: BleakClient
    model_id: int
    anti_spoofing_public_key: ec.EllipticCurvePublicKey
    seeker_key: ec.EllipticCurvePrivateKey
    shared_secret: bytes
    account_key: bytes
    _kbp_response_event: asyncio.Event = asyncio.Event()
    _fhn_response_data: bytes = bytes()
    _fhn_response_event: asyncio.Event = asyncio.Event()

    def __init__(self, device: BLEDevice, advertisement_data: AdvertisementData):
        self.address = device.address
        self.client = BleakClient(device, None, [FAST_PAIR_SERVICE_UUID])
        advertisement = advertisement_data.service_data[FAST_PAIR_SERVICE_UUID]
        if len(advertisement) != 3:
            raise Exception(f"Device is not in pairing mode ({advertisement.hex()})")
        self.model_id = int.from_bytes(
            advertisement_data.service_data[FAST_PAIR_SERVICE_UUID]
        )
        try:
            public_key_point = b"\x04" + KNOWN_ANTI_SPOOFING_PUBLIC_KEYS[self.model_id]
        except KeyError:
            print(
                f"{self.address} | Unknown anti-spoofing public key for model ID {self.model_id:#x}"
            )
            raise
        self.anti_spoofing_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), public_key_point
        )
        self.seeker_key = ec.generate_private_key(ec.SECP256R1())
        digest = Hash(SHA256())
        digest.update(
            self.seeker_key.exchange(ec.ECDH(), self.anti_spoofing_public_key)
        )
        self.shared_secret = digest.finalize()[:16]
        print(f"{self.address} | Shared Secret: {self.shared_secret.hex()}")
        self.account_key = b"\x04" + secrets.token_bytes(15)
        print(f"{self.address} | Account Key: {self.account_key.hex()}")
        self.ephemeral_identity_key = secrets.token_bytes(32)
        print(
            f"{self.address} | Ephemeral Identity Key: {self.ephemeral_identity_key.hex()}"
        )

    def _aes_decrypt(self, key: bytes, message: bytes):
        decryptor = Cipher(algorithms.AES128(key), modes.ECB()).decryptor()
        return decryptor.update(message) + decryptor.finalize()

    def _aes_encrypt(self, key: bytes, message: bytes):
        encryptor = Cipher(algorithms.AES128(key), modes.ECB()).encryptor()
        return encryptor.update(message) + encryptor.finalize()

    def _hmac_sha256(self, key: bytes, message: bytes):
        hmac = HMAC(key, SHA256())
        hmac.update(message)
        return hmac.finalize()

    async def _write_kbp_request(self):
        raw_request = bytearray(16)
        raw_request[0] = 0x00
        raw_request[1] = 0x00
        raw_request[2:8] = bytes.fromhex(self.address.replace(":", ""))
        raw_request[8:16] = secrets.token_bytes(8)
        request = bytearray(80)
        request[0:16] = self._aes_encrypt(self.shared_secret, raw_request)
        request[16:80] = self.seeker_key.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )[1:]
        print(f"{self.address} | Writing key-based pairing request...")
        self._kbp_response_event.clear()
        await self.client.write_gatt_char(
            KEY_BASED_PAIRING_CHARACTERISTIC, request, response=True
        )
        await self._kbp_response_event.wait()

    async def _handle_kbp_response(
        self, characteristic: BleakGATTCharacteristic, data: bytearray
    ):
        print(f"{self.address} | Got key-based pairing response...")
        raw_response = self._aes_decrypt(self.shared_secret, data)
        if raw_response[0] != 0x01:
            raise ValueError(f"Bad key-based pairing response: {raw_response.hex()}")
        self.public_address = ":".join(format(b, "02x") for b in raw_response[1:7])
        print(
            f"{self.address} | Provider's public BR/EDR address: {self.public_address}"
        )
        self._kbp_response_event.set()

    async def _write_account_key(self):
        request = self._aes_encrypt(self.shared_secret, self.account_key)
        print(f"{self.address} | Writing account key...")
        await self.client.write_gatt_char(
            ACCOUNT_KEY_CHARACTERISTIC, request, response=True
        )

    async def _handle_fhn_response(
        self, characteristic: BleakGATTCharacteristic, data: bytearray
    ):
        self._fhn_response_data = data
        self._fhn_response_event.set()

    async def _do_fhn_beacon_operation(self, key: bytes, request: bytearray) -> bytes:
        nonce = await self.client.read_gatt_char(
            BEACON_ACTIONS_CHARACTERISTIC, use_cached=False
        )
        if len(nonce) != 9 or nonce[0] != 0x01:
            raise ValueError(f"Bad FHN beacon nonce: {nonce.hex()}")
        request[1] = len(request) - 2
        request[2:10] = self._hmac_sha256(key, nonce + request[:2] + request[10:])[:8]
        self._fhn_response_event.clear()
        await self.client.write_gatt_char(
            BEACON_ACTIONS_CHARACTERISTIC, request, response=True
        )
        await self._fhn_response_event.wait()
        response = self._fhn_response_data
        signature = self._hmac_sha256(
            key, nonce + response[:2] + response[10:] + b"\x01"
        )[:8]
        if response[0] != request[0] or response[2:10] != signature[:8]:
            raise ValueError(f"Bad FHN beacon response: {response.hex()}")
        return response[10:]

    async def _read_fhn_beacon_parameters(self) -> bytes:
        request = bytearray(10)
        request[0] = 0x00
        response = await self._do_fhn_beacon_operation(self.account_key, request)
        raw_response = self._aes_decrypt(self.account_key, response)
        if raw_response[8:16] != bytes(8):
            raise ValueError(f"Bad FHN beacon parameter response: {raw_response.hex()}")
        clock_value = int.from_bytes(raw_response[1:5])
        self.clock_offset = time.time() - clock_value
        print(
            f"{self.address} | Clock offset: {self.clock_offset} (value={clock_value})"
        )
        self.eid_curve = "secp256r1" if raw_response[5] else "secp160r1"
        print(f"{self.address} | EID curve: {self.eid_curve}")
        return raw_response

    async def _set_fhn_ephemeral_identity_key(self):
        request = bytearray(42)
        request[0] = 0x02
        request[10:42] = self._aes_encrypt(
            self.account_key, self.ephemeral_identity_key
        )
        print(f"{self.address} | Setting ephemeral identity key...")
        await self._do_fhn_beacon_operation(self.account_key, request)

    async def _provision_fhn_beacon(self):
        await self.client.start_notify(
            BEACON_ACTIONS_CHARACTERISTIC, self._handle_fhn_response
        )
        print(f"{self.address} | Provisioning Find Hub Network beacon...")
        await self._read_fhn_beacon_parameters()
        await self._set_fhn_ephemeral_identity_key()

    async def pair(self):
        print(f"{self.address} | Connecting...")
        async with self.client:
            await self.client.start_notify(
                KEY_BASED_PAIRING_CHARACTERISTIC, self._handle_kbp_response
            )
            print(f"{self.address} | Starting key-based pairing...")
            await self._write_kbp_request()
            await self._write_account_key()
            try:
                await self._provision_fhn_beacon()
            except BleakCharacteristicNotFoundError:
                print(
                    f"{self.address} | Not a Find Hub Network beacon, skipping provisioning"
                )
                pass
            print(f"{self.address} | Done!")


async def main():
    async with asyncio.TaskGroup() as tg:
        fast_pair_tasks = {}

        def start_fast_pair(device: BLEDevice, advertisement_data: AdvertisementData):
            address = device.address
            if address in fast_pair_tasks:
                return
            print(f"{address} | Discovered new device")
            try:
                fast_pair_tasks[address] = tg.create_task(
                    FastPairHandshake(device, advertisement_data).pair()
                )
            except Exception as e:
                print(
                    f"{address} | Failed to start Fast Pair handshake: {type(e)}: {e}"
                )

        async with BleakScanner(start_fast_pair, [FAST_PAIR_SERVICE_UUID]) as scanner:
            await asyncio.sleep(10)


if __name__ == "__main__":
    asyncio.run(main())
