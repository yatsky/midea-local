"""Midea local CC message."""

import struct
from enum import IntEnum

from midealocal.const import DeviceType
from midealocal.message import (
    ListTypes,
    MessageBody,
    MessageRequest,
    MessageResponse,
    MessageType,
)


class CCControlId(IntEnum):
    """VNT8 CC device control IDs (TLV protocol)."""

    POWER = 0x0000
    TARGET_TEMPERATURE = 0x0003
    TEMPERATURE_UNIT = 0x000C
    TARGET_HUMIDITY = 0x000F
    MODE = 0x0012
    FAN_SPEED = 0x0015
    VERT_SWING_ANGLE = 0x001C
    HORZ_SWING_ANGLE = 0x001E
    WIND_SENSE = 0x0020
    ECO = 0x0028
    SILENT = 0x002A
    SLEEP = 0x002C
    SELF_CLEAN = 0x002E
    PURIFIER = 0x003A
    BEEP = 0x003F
    DISPLAY = 0x0040
    AUX_MODE = 0x0043


class CCHeatStatus(IntEnum):
    """CC Heat Status."""

    X10 = 1
    X20 = 2


class MessageCCBase(MessageRequest):
    """CC message base."""

    def __init__(
        self,
        protocol_version: int,
        message_type: MessageType,
        body_type: ListTypes,
    ) -> None:
        """Initialize CC message base."""
        super().__init__(
            device_type=DeviceType.CC,
            protocol_version=protocol_version,
            message_type=message_type,
            body_type=body_type,
        )

    @property
    def _body(self) -> bytearray:
        raise NotImplementedError


class MessageQuery(MessageCCBase):
    """CC message query."""

    def __init__(self, protocol_version: int) -> None:
        """Initialize CC message query."""
        super().__init__(
            protocol_version=protocol_version,
            message_type=MessageType.query,
            body_type=ListTypes.X01,
        )

    @property
    def _body(self) -> bytearray:
        return bytearray([0x00] * 23)


class MessageSet(MessageCCBase):
    """CC message set."""

    def __init__(self, protocol_version: int) -> None:
        """Initialize CC message set."""
        super().__init__(
            protocol_version=protocol_version,
            message_type=MessageType.set,
            body_type=ListTypes.C3,
        )
        self.power = False
        self.mode = 4
        self.fan_speed = 0x80
        self.target_temperature: float = 26
        self.eco_mode = False
        self.sleep_mode = False
        self.night_light = False
        self.ventilation = False
        self.aux_heat_status = 0
        self.auto_aux_heat_running = False
        self.swing = False

    @property
    def _body(self) -> bytearray:
        # Byte1, Power Mode
        power = 0x80 if self.power else 0
        mode = 1 << (self.mode - 1)
        # Byte2 fan_speed
        fan_speed = self.fan_speed
        # Byte3 Integer of target_temperature
        temperature_integer = int(self.target_temperature) & 0xFF
        # Byte6 eco_mode ventilation aux_heating
        eco_mode = 0x01 if self.eco_mode else 0
        if self.aux_heat_status == CCHeatStatus.X10:
            aux_heating = 0x10
        elif self.aux_heat_status == CCHeatStatus.X20:
            aux_heating = 0x20
        else:
            aux_heating = 0
        swing = 0x04 if self.swing else 0
        ventilation = 0x08 if self.ventilation else 0
        # Byte8 sleep_mode night_light
        sleep_mode = 0x10 if self.sleep_mode else 0
        night_light = 0x08 if self.night_light else 0
        # Byte11 Dot of target_temperature
        temperature_dot = (
            int((self.target_temperature - temperature_integer) * 10) & 0xFF
        )
        return bytearray(
            [
                power | mode,
                fan_speed,
                temperature_integer,
                # timer
                0x00,
                0x00,
                eco_mode | ventilation | swing | aux_heating,
                # non-stepless fan speed
                0xFF,
                sleep_mode | night_light,
                0x00,
                0x00,
                temperature_dot,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            ],
        )


class CCTLVMessageSet(MessageCCBase):
    """VNT8 CC SET — real TLV-record encoding.

    Based on the reverse-engineered protocol in mill1000/midea-msmart
    (msmart/device/CC/command.py::ControlCommand). Each control is sent
    as a TLV record:

        [ID_hi ID_lo LEN VALUE 0xFF]

    After all records: 1-byte message_id (incrementing) + 1-byte CRC-8/854
    over (records + message_id). The body has NO body_type prefix byte
    (unlike midealocal's other set messages); we set _body_type=None
    after super().__init__ to suppress the framework prefix.

    Mode mapping (midealocal attr -> raw byte the AC expects):
      1 (auto) -> 5
      2 (cool) -> 2
      3 (heat) -> 3
      4 (dry)  -> 6
    Fan speed is sequential 1..7 + 8 for auto (NOT bitmask like the
    legacy _fan_speeds_7level dict).
    """

    # Control IDs (from CCControlId, duplicated as plain ints to avoid
    # an enum import dependency cycle).
    _ID_POWER = 0x0000
    _ID_TARGET_TEMP = 0x0003
    _ID_MODE = 0x0012
    _ID_FAN_SPEED = 0x0015
    _ID_ECO = 0x0028
    _ID_SLEEP = 0x002C

    # CRC-8/854 lookup table (lifted from mill1000/midea-msmart).
    _CRC8_854_TABLE = (
        0x00, 0x5E, 0xBC, 0xE2, 0x61, 0x3F, 0xDD, 0x83,
        0xC2, 0x9C, 0x7E, 0x20, 0xA3, 0xFD, 0x1F, 0x41,
        0x9D, 0xC3, 0x21, 0x7F, 0xFC, 0xA2, 0x40, 0x1E,
        0x5F, 0x01, 0xE3, 0xBD, 0x3E, 0x60, 0x82, 0xDC,
        0x23, 0x7D, 0x9F, 0xC1, 0x42, 0x1C, 0xFE, 0xA0,
        0xE1, 0xBF, 0x5D, 0x03, 0x80, 0xDE, 0x3C, 0x62,
        0xBE, 0xE0, 0x02, 0x5C, 0xDF, 0x81, 0x63, 0x3D,
        0x7C, 0x22, 0xC0, 0x9E, 0x1D, 0x43, 0xA1, 0xFF,
        0x46, 0x18, 0xFA, 0xA4, 0x27, 0x79, 0x9B, 0xC5,
        0x84, 0xDA, 0x38, 0x66, 0xE5, 0xBB, 0x59, 0x07,
        0xDB, 0x85, 0x67, 0x39, 0xBA, 0xE4, 0x06, 0x58,
        0x19, 0x47, 0xA5, 0xFB, 0x78, 0x26, 0xC4, 0x9A,
        0x65, 0x3B, 0xD9, 0x87, 0x04, 0x5A, 0xB8, 0xE6,
        0xA7, 0xF9, 0x1B, 0x45, 0xC6, 0x98, 0x7A, 0x24,
        0xF8, 0xA6, 0x44, 0x1A, 0x99, 0xC7, 0x25, 0x7B,
        0x3A, 0x64, 0x86, 0xD8, 0x5B, 0x05, 0xE7, 0xB9,
        0x8C, 0xD2, 0x30, 0x6E, 0xED, 0xB3, 0x51, 0x0F,
        0x4E, 0x10, 0xF2, 0xAC, 0x2F, 0x71, 0x93, 0xCD,
        0x11, 0x4F, 0xAD, 0xF3, 0x70, 0x2E, 0xCC, 0x92,
        0xD3, 0x8D, 0x6F, 0x31, 0xB2, 0xEC, 0x0E, 0x50,
        0xAF, 0xF1, 0x13, 0x4D, 0xCE, 0x90, 0x72, 0x2C,
        0x6D, 0x33, 0xD1, 0x8F, 0x0C, 0x52, 0xB0, 0xEE,
        0x32, 0x6C, 0x8E, 0xD0, 0x53, 0x0D, 0xEF, 0xB1,
        0xF0, 0xAE, 0x4C, 0x12, 0x91, 0xCF, 0x2D, 0x73,
        0xCA, 0x94, 0x76, 0x28, 0xAB, 0xF5, 0x17, 0x49,
        0x08, 0x56, 0xB4, 0xEA, 0x69, 0x37, 0xD5, 0x8B,
        0x57, 0x09, 0xEB, 0xB5, 0x36, 0x68, 0x8A, 0xD4,
        0x95, 0xCB, 0x29, 0x77, 0xF4, 0xAA, 0x48, 0x16,
        0xE9, 0xB7, 0x55, 0x0B, 0x88, 0xD6, 0x34, 0x6A,
        0x2B, 0x75, 0x97, 0xC9, 0x4A, 0x14, 0xF6, 0xA8,
        0x74, 0x2A, 0xC8, 0x96, 0x15, 0x4B, 0xA9, 0xF7,
        0xB6, 0xE8, 0x0A, 0x54, 0xD7, 0x89, 0x6B, 0x35,
    )

    # midealocal attr mode -> raw byte the AC expects.
    _MODE_ATTR_TO_RAW = {1: 5, 2: 2, 3: 3, 4: 6}

    _message_id_counter = 0

    def __init__(self, protocol_version: int) -> None:
        """Initialize a TLV SET; controls are added by the caller."""
        super().__init__(
            protocol_version=protocol_version,
            message_type=MessageType.set,
            body_type=ListTypes.X00,
        )
        # VNT8 TLV body has no body_type prefix — bypass framework default.
        self._body_type = None
        self.power: bool | None = None
        self.target_temperature: float | None = None
        self.mode: int | None = None
        self.fan_speed: int | None = None
        self.eco_mode: bool | None = None
        self.sleep_mode: bool | None = None
        # Accepted via setattr() from set_attribute() for compat; unused.
        self.night_light = False
        self.aux_heat_status = 0
        self.swing = False
        self.ventilation = False

    @classmethod
    def _next_message_id(cls) -> int:
        cls._message_id_counter = (cls._message_id_counter + 1) & 0xFF
        return cls._message_id_counter

    @classmethod
    def _crc8(cls, data: bytes) -> int:
        crc = 0
        for b in data:
            crc = cls._CRC8_854_TABLE[(crc ^ b) & 0xFF]
        return crc

    @property
    def _body(self) -> bytearray:
        body = bytearray()

        def _record(ctrl_id: int, value: bytes) -> None:
            body.extend(struct.pack(">H", ctrl_id))
            body.append(len(value))
            body.extend(value)
            body.append(0xFF)

        if self.power is not None:
            _record(self._ID_POWER, bytes([0x01 if self.power else 0x00]))
        if self.target_temperature is not None:
            _record(
                self._ID_TARGET_TEMP,
                bytes([int((2 * self.target_temperature) + 80) & 0xFF]),
            )
        if self.mode is not None:
            raw_mode = self._MODE_ATTR_TO_RAW.get(int(self.mode), int(self.mode))
            _record(self._ID_MODE, bytes([raw_mode & 0xFF]))
        if self.fan_speed is not None:
            _record(self._ID_FAN_SPEED, bytes([int(self.fan_speed) & 0xFF]))
        if self.eco_mode is not None:
            _record(self._ID_ECO, bytes([0x01 if self.eco_mode else 0x00]))
        if self.sleep_mode is not None:
            _record(self._ID_SLEEP, bytes([0x01 if self.sleep_mode else 0x00]))

        # Append message_id then CRC8 over (records + msg_id)
        body.append(self._next_message_id())
        body.append(self._crc8(bytes(body)))
        return body


class CCGeneralMessageBody(MessageBody):
    """CC message general body (old fixed-offset protocol)."""

    def __init__(self, body: bytearray) -> None:
        """Initialize CC message general body."""
        super().__init__(body)
        self.power = (body[1] & 0x80) > 0
        mode: float = body[1] & 0x1F
        self.mode = 0
        while mode >= 1:
            mode /= 2
            self.mode += 1
        self.fan_speed = body[2]
        self.target_temperature = body[3] + body[19] / 10
        self.indoor_temperature = (body[4] - 40) / 2
        self.eco_mode = (body[13] & 0x01) > 0
        self.sleep_mode = (body[14] & 0x10) > 0
        self.night_light = (body[14] & 0x08) > 0
        self.ventilation = (body[13] & 0x08) > 0
        self.aux_heat_status = (body[14] & 0x60) >> 5
        self.auto_aux_heat_running = (body[13] & 0x02) > 0
        self.fan_speed_level = (body[13] & 0x40) > 0
        self.temperature_precision = 1 if (body[14] & 0x80) > 0 else 0.5
        self.swing = (body[13] & 0x04) > 0
        self.temp_fahrenheit = (body[20] & 0x80) > 0


class CCTLVMessageBody(MessageBody):
    """VNT8 CC message body decoded from TLV (Type-Length-Value) protocol.

    This handles the newer VNT8 protocol used by MDV multi-split CC devices,
    where the response uses a 0x01 0xFE header followed by structured data
    with ControlId-keyed fields at known byte offsets.
    """

    def __init__(self, body: bytearray) -> None:
        """Parse VNT8 TLV query response body."""
        super().__init__(body)
        # The 0x01 0xFE header is already stripped by the caller
        # body[0:8] = header section
        # body[8:]  = data section

        self.power = body[8] > 0
        # target_temperature: encoded as (data / 2) - 40
        self.target_temperature = (body[11] / 2.0) - 40
        # indoor_temperature: 2-byte big-endian, value / 10
        self.indoor_temperature = ((body[12] << 8) | body[13]) / 10.0
        # outdoor_temperature: same encoding as target if non-zero
        outdoor_raw = body[14]
        if outdoor_raw:
            self.outdoor_temperature = (outdoor_raw / 2.0) - 40
        else:
            self.outdoor_temperature = None

        self.mode = 0
        mode_raw = body[31]
        mode_map = {1: 1, 2: 2, 3: 3, 5: 1, 6: 4}
        self.mode = mode_map.get(mode_raw, 1)
        # Default values for attributes not in TLV response
        self.fan_speed = body[34] if len(body) > 34 else 0x80
        self.eco_mode = body[56] > 0 if len(body) > 56 else False
        self.sleep_mode = body[60] > 0 if len(body) > 60 else False
        self.night_light = False  # Not in VNT8 TLV
        self.ventilation = False  # Not in VNT8 TLV
        self.aux_heat_status = 0
        self.auto_aux_heat_running = False
        self.fan_speed_level = bool(body[32] if len(body) > 32 else 0)
        self.temperature_precision = 1  # VNT8 uses 0.5C stepping
        self.swing = False
        self.temp_fahrenheit = body[21] > 0 if len(body) > 21 else False

    def parse_capabilities(self) -> None:
        """Parse capabilities from VNT8 TLV response (body offset index).

        Called after initial parse to fill in device capability fields.
        """
        body = self._data
        if len(body) >= 11:
            self.target_temperature_min = (body[9] / 2.0) - 40 if body[9] else 17
            self.target_temperature_max = (body[10] / 2.0) - 40 if body[10] else 30


class MessageCCResponse(MessageResponse):
    """CC message response."""

    def __init__(self, message: bytes) -> None:
        """Initialize CC message response."""
        super().__init__(bytearray(message))
        if (
            (self.message_type == MessageType.query and self.body_type == ListTypes.X01)
            or (
                self.message_type in [MessageType.notify1, MessageType.notify2]
                and self.body_type == ListTypes.X01
            )
            or (self.message_type == MessageType.set and self.body_type == ListTypes.C3)
        ):
            raw_body = super().body
            # Detect VNT8 TLV protocol: body starts with 0x01 0xFE
            if len(raw_body) >= 2 and raw_body[0] == 0x01 and raw_body[1] == 0xFE:
                message_body = CCTLVMessageBody(raw_body)
                # Parse capabilities from same response
                message_body.parse_capabilities()
                self.set_body(message_body)
            else:
                # Old-style fixed-offset CC protocol
                self.set_body(CCGeneralMessageBody(raw_body))
        self.set_attr()
