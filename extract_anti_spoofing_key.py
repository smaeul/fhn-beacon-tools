# SPDX-License-Identifier: BSD-2-Clause

import plyvel

from argparse import ArgumentParser
from dataclasses import dataclass
from io import BytesIO
from pure_protobuf.annotations import Field, fixed32
from pure_protobuf.message import BaseMessage
from typing_extensions import Annotated


@dataclass
class AntiSpoofingInfo(BaseMessage):
    public_key: Annotated[bytes, Field(2)]


@dataclass
class FastPairModelInfo(BaseMessage):
    model_id: Annotated[int, Field(1)]
    unk3: Annotated[int, Field(3)]
    image_url: Annotated[str, Field(4)]
    name: Annotated[str, Field(5)]
    intent: Annotated[str, Field(6)]
    unk8: Annotated[fixed32, Field(8)]
    anti_spoofing_info: Annotated[AntiSpoofingInfo, Field(9)]
    unk13: Annotated[int, Field(13)]
    unk15: Annotated[str, Field(15)]
    unk18: Annotated[int, Field(18)]
    manufacturer: Annotated[str, Field(19)]


@dataclass
class FastPairItemInfo(BaseMessage):
    model_info: Annotated[FastPairModelInfo, Field(1)]


@dataclass
class NearbyScanFastPairDBItem(BaseMessage):
    key: Annotated[str, Field(1)]
    value: Annotated[FastPairItemInfo, Field(2)]


def main():
    parser = ArgumentParser()
    parser.add_argument("db_path")
    args = parser.parse_args()

    with plyvel.DB(args.db_path) as db:
        for key, value in db:
            item = NearbyScanFastPairDBItem.read_from(BytesIO(value))
            model_info = item.value.model_info
            print(f"    # {model_info.manufacturer} - {model_info.name}")
            print(
                f'    {model_info.model_id:#x}: bytes.fromhex("{model_info.anti_spoofing_info.public_key.hex()}"),'
            )


if __name__ == "__main__":
    main()
