# Source: https://github.com/tinytag/tinytag
# Ref: 39e5d0e5463abac597b3292feb9c2e409eee1e34 Path: tinytag/tinytag.py
# Excerpted and modified from https://github.com/tinytag/tinytag@39e5d0e5463abac597b3292feb9c2e409eee1e34 on 2026-10-20
# License: MIT, see licenses/tinytag__tinytag/LICENSE
# Copyright (c) 2014-2026 Tom Wallroth, Mat (mathiascode), et al.
class _MP4(TinyTag):
    """MP4 Audio Parser.

    https://developer.apple.com/library/mac/documentation/QuickTime/QTFF/Metadata/Metadata.html
    https://developer.apple.com/library/mac/documentation/QuickTime/QTFF/QTFFChap2/qtff2.html
    """

    _CUSTOM_FIELD_NAME_MAPPING = {
        'artists': 'artist',
        'conductor': 'other.conductor',
        'discsubtitle': 'other.set_subtitle',
        'initialkey': 'other.initial_key',
        'isrc': 'other.isrc',
        'language': 'other.language',
        'lyricist': 'other.lyricist',
        'media': 'other.media',
        'website': 'other.url',
        'license': 'other.license',
        'barcode': 'other.barcode',
        'catalognumber': 'other.catalog_number',
    }
    _IMAGE_MIME_TYPES = {
        12: 'image/gif',
        13: 'image/jpeg',
        14: 'image/png',
        27: 'image/bmp'
    }
    _UNPACK_FORMATS = {
        1: '>b',
        2: '>h',
        4: '>i',
        8: '>q'
    }
    _VERSIONED_ATOMS = {b'meta', b'stsd'}  # those have an extra 4 byte header
    _FLAGGED_ATOMS = {b'stsd'}  # these also have an extra 4 byte header
    _ILST_PATH = [b'ftyp', b'moov', b'udta', b'meta', b'ilst']

    _audio_data_tree: _DataTreeDict | None = None
    _meta_data_tree: _DataTreeDict | None = None
    _combined_tree: _DataTreeDict | None = None

    def _parse(self, fh: BinaryIO) -> None:
        # The parser tree: Each key is an atom name which is traversed if
        # existing. Leaves of the parser tree are callables which receive
        # the atom data. Callables return {fieldname: value} which is updates
        # the TinyTag.
        tree = {}
        if self._parse_duration and self._parse_tags:
            tree = self._build_combined_tree()
        elif self._parse_duration:
            tree = self._build_audio_data_tree()
        elif self._parse_tags:
            tree = self._build_meta_data_tree()
        self._traverse_atoms(fh, path=tree)
        self._duration_parsed = self._parse_duration
        self._tags_parsed = self._parse_tags

    @classmethod
    def _build_audio_data_tree(cls) -> _DataTreeDict:
        if cls._audio_data_tree is None:
            # https://developer.apple.com/library/mac/documentation/QuickTime/QTFF/QTFFChap3/qtff3.html
            cls._audio_data_tree = {
                b'moov': {
                    b'mvhd': _MP4._parse_mvhd,
                    b'trak': {b'mdia': {b"minf": {b"stbl": {b"stsd": {
                        b'mp4a': _MP4._parse_mp4a,
                        b'alac': _MP4._parse_alac
                    }}}}}
                }
            }
        return cls._audio_data_tree

    @classmethod
    def _build_meta_data_tree(cls) -> _DataTreeDict:
        if cls._meta_data_tree is None:
            cls._meta_data_tree = {b'moov': {b'udta': {b'meta': {b'ilst': {
                # http://atomicparsley.sourceforge.net/mpeg-4files.html
                # https://metacpan.org/dist/Image-ExifTool/source/lib/Image/ExifTool/QuickTime.pm#L3093
                b'\xA9ART': {b'data': _MP4._data_parser('artist')},
                b'\xA9alb': {b'data': _MP4._data_parser('album')},
                b'\xA9cmt': {b'data': _MP4._data_parser('comment')},
                b'\xA9com': {b'data': _MP4._data_parser('composer')},
                b'\xA9con': {b'data': _MP4._data_parser('other.conductor')},
                b'\xA9day': {b'data': _MP4._data_parser('year')},
                b'\xA9des': {b'data': _MP4._data_parser('other.description')},
                b'\xA9dir': {b'data': _MP4._data_parser('other.director')},
                b'\xA9gen': {b'data': _MP4._data_parser('genre')},
                b'\xA9grp': {b'data': _MP4._data_parser('other.grouping')},
                b'\xA9lyr': {b'data': _MP4._data_parser('other.lyrics')},
                b'\xA9mvc': {
                    b'data': _MP4._data_parser('other.movement_total')
                },
                b'\xA9mvi': {b'data': _MP4._data_parser('other.movement')},
                b'\xA9mvn': {
                    b'data': _MP4._data_parser('other.movement_name')
                },
                b'\xA9nam': {b'data': _MP4._data_parser('title')},
                b'\xA9pub': {b'data': _MP4._data_parser('other.publisher')},
                b'\xA9too': {b'data': _MP4._data_parser('other.encoded_by')},
                b'\xA9wrk': {b'data': _MP4._data_parser('other.work')},
                b'\xA9wrt': {b'data': _MP4._data_parser('composer')},
                b'aART': {b'data': _MP4._data_parser('albumartist')},
                b'cprt': {b'data': _MP4._data_parser('other.copyright')},
                b'desc': {b'data': _MP4._data_parser('other.description')},
                b'disk': {b'data': _MP4._nums_parser('disc', 'disc_total')},
                b'gnre': {b'data': _MP4._parse_id3v1_genre},
                b'shwm': {b'data': _MP4._data_parser('other.show_movement')},
                b'trkn': {b'data': _MP4._nums_parser('track', 'track_total')},
                b'tmpo': {b'data': _MP4._data_parser('other.bpm')},
                b'covr': {b'data': _MP4._parse_cover_image},
                b'----': _MP4._parse_custom_field,
            }}}}, b'uuid': _MP4._parse_uuid}
        return cls._meta_data_tree

    @classmethod
    def _build_combined_tree(cls) -> _DataTreeDict:
        if cls._combined_tree is None:
            cls._combined_tree = result = dict(cls._build_audio_data_tree())
            for key, value in cls._build_meta_data_tree().items():
                current = result.get(key)
                if isinstance(current, dict) and isinstance(value, dict):
                    result[key] = {**current, **value}
                else:
                    result[key] = value
        return cls._combined_tree

    def _traverse_atoms(self,
                        fh: BinaryIO,
                        path: _DataTreeDict,
                        stop_pos: int | None = None,
                        curr_path: list[bytes] | None = None) -> None:
        header_len = ext_size_len = 8
        atom_header = fh.read(header_len)
        if curr_path is None:
            atom_type = atom_header[4:]
            # Should be safe enough for a quick header check. Newer MP4
            # files tend to start with an 'ftyp' atom. Older files don't,
            # but their initial atom type only seem to use ASCII chars.
            if len(atom_type) != 4 or not atom_type.isascii():
                raise ParseError('Invalid MP4 header')
            self.mime_type = 'audio/mp4'
        while len(atom_header) == header_len:
            atom_size = unpack_from('>I', atom_header)[0]
            atom_type = atom_header[4:]
            if curr_path is None:
                curr_path = [atom_type]
            if atom_size == 1:  # 64-bit size
                ext_size_header = fh.read(ext_size_len)
                if len(ext_size_header) == ext_size_len:
                    atom_size = unpack('>Q', ext_size_header)[0] - ext_size_len
            atom_size -= header_len
            if atom_size <= 0:  # empty atom, jump to next one
                atom_header = fh.read(header_len)
                continue
            if _DEBUG:
                print(f'{" " * 4 * len(curr_path)} '
                      f'pos: {fh.tell() - header_len} '
                      f'atom: {atom_type!r} len: {atom_size + header_len}')
            if atom_type in self._VERSIONED_ATOMS:  # jump atom version for now
                fh.seek(4, SEEK_CUR)
                atom_size -= 4
            if atom_type in self._FLAGGED_ATOMS:  # jump atom flags for now
                fh.seek(4, SEEK_CUR)
                atom_size -= 4
            sub_path = path.get(atom_type, None)
            # if the path leaf is a dict, traverse deeper into the tree:
            if isinstance(sub_path, dict):
                atom_end_pos = fh.tell() + atom_size
                self._traverse_atoms(fh, path=sub_path, stop_pos=atom_end_pos,
                                     curr_path=curr_path + [atom_type])
            # if the path-leaf is a callable, call it on the atom data
            elif callable(sub_path):
                for fieldname, value in sub_path(fh.read(atom_size)):
                    if _DEBUG:
                        print(' ' * 4 * len(curr_path), 'FIELD: ', fieldname)
                    if isinstance(value, Image):
                        if self._load_image:
                            # pylint: disable=protected-access
                            self.images._set_field(fieldname, value)
                    elif isinstance(value, list):
                        for subval in value:
                            self._set_field(fieldname, subval)
                    elif fieldname == 'codec':
                        self.mime_type = f'audio/mp4; codecs="{value}"'
                    else:
                        self._set_field(fieldname, value)
            # unknown data atom, try to parse it
            elif curr_path == self._ILST_PATH:
                atom_end_pos = fh.tell() + atom_size
                field_name = (
                    self._OTHER_PREFIX + atom_type.decode('latin-1').lower()
                )
                fh.seek(-header_len, SEEK_CUR)
                self._traverse_atoms(
                    fh,
                    path={atom_type: {b'data': self._data_parser(field_name)}},
                    stop_pos=atom_end_pos, curr_path=curr_path + [atom_type])
            # if no action was specified using dict or callable, jump over atom
            else:
                fh.seek(atom_size, SEEK_CUR)
            # check if we have reached the end of this branch:
            if stop_pos and fh.tell() >= stop_pos:
                return  # return to parent (next parent node in tree)
            atom_header = fh.read(header_len)  # read next atom

    @classmethod
    def _data_parser(
        cls, fieldname: str
    ) -> Callable[[bytes], Iterator[tuple[str, str]]]:
        def _parse_data_atom(data_atom: bytes) -> Iterator[tuple[str, str]]:
            data_type = unpack_from('>I', data_atom)[0]
            data = data_atom[8:]
            value = ""
            if data_type == 1:     # UTF-8 string
                value = data.decode('utf-8', 'replace')
            elif data_type == 21:  # BE signed integer
                fmts = cls._UNPACK_FORMATS
                data_len = len(data)
                if data_len in fmts:
                    value = str(unpack(fmts[data_len], data)[0])
            yield fieldname, value
        return _parse_data_atom

    @classmethod
    def _nums_parser(
        cls, fieldname1: str, fieldname2: str
    ) -> Callable[[bytes], Iterator[tuple[str, int]]]:
        def _parse_nums(data_atom: bytes) -> Iterator[tuple[str, int]]:
            number_data = data_atom[8:14]
            numbers = unpack('>3H', number_data)
            # for some reason the first number is always irrelevant.
            yield fieldname1, numbers[1]
            yield fieldname2, numbers[2]
        return _parse_nums

    @classmethod
    def _parse_id3v1_genre(cls, data_atom: bytes) -> Iterator[tuple[str, str]]:
        # dunno why genre is offset by -1 but that's how mutagen does it
        idx = unpack_from('>H', data_atom, 8)[0] - 1
        # pylint: disable=protected-access
        if idx < len(_ID3._ID3V1_GENRES):
            yield 'genre', _ID3._ID3V1_GENRES[idx]

    @classmethod
    def _parse_cover_image(cls,
                           data_atom: bytes) -> Iterator[tuple[str, Image]]:
        data_type = unpack_from('>I', data_atom)[0]
        image_name = 'front_cover'
        image_data = data_atom[8:]
        image = Image(
            image_name, len(image_data), image_data,
            cls._IMAGE_MIME_TYPES.get(data_type))
        yield image_name, image

    @classmethod
    def _parse_custom_field(cls,
                            data: bytes) -> Iterator[tuple[str, list[str]]]:
        fh = BytesIO(data)
        header_len = 8
        field_name = None
        values = []
        atom_header = fh.read(header_len)
        while len(atom_header) == header_len:
            atom_size = unpack_from('>I', atom_header)[0] - header_len
            atom_type = atom_header[4:]
            if atom_type == b'name':
                atom_value = fh.read(atom_size)[4:].lower()
                field_name = atom_value.decode('utf-8', 'replace')
                # pylint: disable=protected-access
                field_name = cls._CUSTOM_FIELD_NAME_MAPPING.get(
                    field_name, cls._OTHER_PREFIX + field_name)
            elif atom_type == b'data' and field_name:
                data_atom = fh.read(atom_size)
                parser = cls._data_parser(field_name)
                atom_values = parser(data_atom)
                for _field_name, value in atom_values:
                    values.append(value)
                    break
            else:
                fh.seek(atom_size, SEEK_CUR)
            atom_header = fh.read(header_len)  # read next atom
        if field_name and values:
            yield field_name, values

    @classmethod
    def _parse_uuid(cls, data_atom: bytes) -> Iterator[tuple[str, str]]:
        uuid_len = 16
        uuid = data_atom[:uuid_len]
        if uuid == (
            b'\xBE\x7A\xCF\xCB\x97\xA9\x42\xE8\x9C\x71\x99\x94\x91\xE3\xAF\xAC'
        ):
            yield 'other.xmp', data_atom[uuid_len:].decode('utf-8', 'replace')

    @classmethod
    def _parse_mp4a(cls, data: bytes) -> Iterator[tuple[str, str | float]]:
        # this atom also contains the esds atom:
        # https://ffmpeg.org/doxygen/0.6/mov_8c-source.html
        # http://xhelmboyx.tripod.com/formats/mp4-layout.txt
        # http://sasperger.tistory.com/103

        # jump over version and flags
        channels = unpack_from('>H', data, 16)[0]
        yield 'channels', channels
        # jump over bit_depth, QT compr id & pkt size
        sr = unpack_from('>I', data, 22)[0]
        yield 'samplerate', sr

        # ES Description Atom
        def _read_descriptor_size(data: bytes, offset: int) -> tuple[int, int]:
            size = 0
            continuation = 1 << 7
            for _i in range(4):
                byte = data[offset]
                offset += 1
                size = (size << 7) | (byte & ((1 << 7) - 1))
                if not (byte & continuation):
                    break
            return size, offset

        offset = 36 + 5   # jump over version, flags and tag

        # ES Descriptor
        _size, offset = _read_descriptor_size(data, offset)
        offset += 4   # jump over ES id, flags and tag

        # Decoder Config Descriptor
        _size, offset = _read_descriptor_size(data, offset)
        object_type = data[offset]
        codec = f'mp4a.{object_type:X}'
        offset += 9
        avg_br = unpack_from('>I', data, offset)[0]
        if avg_br > 0:
            yield 'bitrate', avg_br / 1000  # kbit/s
        offset += 5

        # Decoder Specific Info
        _size, offset = _read_descriptor_size(data, offset)
        first = data[offset]
        second = data[offset + 1]
        audio_object_type = first >> 3
        if audio_object_type == 31:
            # Read extended value
            extended = ((first & 0x07) << 3) | (second >> 5)
            audio_object_type = 32 + extended
        if audio_object_type:
            codec += f'.{audio_object_type}'
        yield 'codec', codec

    @classmethod
    def _parse_alac(cls, data: bytes) -> Iterator[tuple[str, str | int]]:
        # https://github.com/macosforge/alac/blob/master/ALACMagicCookieDescription.txt
        yield 'codec', 'alac'
        bitdepth = data[45]
        yield 'bitdepth', bitdepth
        channels = data[49]
        yield 'channels', channels
        avg_br, sr = unpack_from('>II', data, 56)
        yield 'samplerate', sr
        avg_br /= 1000  # kbit/s
        yield 'bitrate', avg_br

    @classmethod
    def _parse_mvhd(cls, data: bytes) -> Iterator[tuple[str, float]]:
        # http://stackoverflow.com/a/3639993/1191373
        version = data[0]
        # jump over flags, create & mod times
        if version == 0:  # uses 32 bit integers for timestamps
            time_scale, duration = unpack_from('>II', data, 12)
        else:  # version == 1:  # uses 64-bit integers for timestamps
            time_scale, duration = unpack_from('>IQ', data, 20)
        yield 'duration', duration / time_scale
