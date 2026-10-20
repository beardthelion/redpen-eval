# Judge hand-check worksheet

For each case, read the fenced fields and fill in the four answer lines. Then fill Reviewer and Date and set Signed-off to yes.

## Case 1: GHSA-47c3-hpmg-7j6p (run 20261020T145119Z-reviewer-a-3aec9d76)
Case id: GHSA-47c3-hpmg-7j6p
Guard class: input-validation
Vulnerability description:
```
Client-supplied id joined into a filesystem path in _local_dir without validate_bookmark_id. Path segments from the client must be allowlisted before Path() joins (variant of GHSA-47c3-hpmg-7j6p / CVE-2026-108258).
```
Expected spans: 12-12 (semgrep), 3-4 (fix_diff), 7-8 (fix_diff), 10-11 (fix_diff)
Numbered vuln window:
```
     1  from __future__ import annotations
     2  
     3  import os
     4  from pathlib import Path
     5  
     6  shiny_bookmarks_folder_name = "shiny_bookmarks"
     7  
     8  
     9  def _local_dir(id: str) -> Path:
    10      # Try to save/load from current working directory as we do not know where the
    11      # app file is located
    12      return Path(os.getcwd()) / shiny_bookmarks_folder_name / id
```
Vuln review text:
```
**Finding**

- **File:** `_bookmark_state.py`
- **Line:** 12
- **Vulnerability class:** Path traversal (CWE-22)
- **Quote:** `return Path(os.getcwd()) / shiny_bookmarks_folder_name / id`

`id` is joined into a filesystem path with no check that it is a single safe path segment. Values such as `../` or an absolute path can escape `shiny_bookmarks` and point at arbitrary locations under the process’s working directory (or elsewhere, depending on the value). Callers that save or load using this path inherit that traversal.
```
Vuln judge parsed JSON:
```
{
  "cited_ranges": [
    {
      "end": 12,
      "start": 12
    }
  ],
  "rationale": "The review flags line 12, where the client-supplied `id` is joined into a filesystem path with no check that it is a single safe path segment. This is the same missing allowlist/validation guard and the same path traversal weakness as the known vulnerability.",
  "verdict_class_match": true
}
```
Harness verdict: HIT
Fixed review text:
````
The bookmark-id allowlist blocks `..`, separators, and absolute paths, but three issues remain.

**1. `_bookmark_state.py:20` — CWE-770 (allocation without limits) / CWE-779 (logging of excessive data)**
```python
raise ValueError(f"Invalid bookmark id: {id!r}")
```
The length check on line 19 does not stop the id from being copied into the exception. An over-long client id is still fully interpolated, so the 1024-character log/error guard on line 14 never applies. `!r` only escapes control characters; it does not cap size.

**2. `_bookmark_state.py:12` — CWE-67 (Windows device names)**
```python
_valid_bookmark_id_re = re.compile(r"[A-Za-z0-9_-]+")
```
`fullmatch` rejects `..` and separators, but names such as `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, and `LPT1`–`LPT9` match. On Windows, line 28 then builds a path that file APIs treat as a device, not a directory under `shiny_bookmarks`.

**3. `_bookmark_state.py:28` — CWE-59 (link resolution) / CWE-41 (path equivalence)**
```python
return Path(os.getcwd()) / shiny_bookmarks_folder_name / id
```
The join cannot escape via `..`, but the path is not canonicalized and symlinks are not rejected. A per-id symlink under `shiny_bookmarks` is followed on later open. On case-insensitive volumes, distinct ids such as `Ab` and `ab` also resolve to the same directory, so client-supplied ids can alias another bookmark.
````
Fixed judge parsed JSON:
```
{
  "cited_ranges": [],
  "rationale": "The review acknowledges that the allowlist blocks `..`, separators and absolute paths, so it does not claim the path traversal from the missing validate_bookmark_id is still present. Its three findings (error-message length, Windows device names, symlink/case aliasing) are different issues from the patched vulnerability.",
  "reported_patched_vuln": false
}
```
fixed_clean: true

Human verdict (HIT/PARTIAL/MISS):
Human fixed side (clean/re-reported):
Agree with harness (yes/no):
Notes:

## Case 2: GHSA-24cc-9352-h2pg (run 20261020T145119Z-reviewer-a-3aec9d76)
Case id: GHSA-24cc-9352-h2pg
Guard class: type-range-check
Vulnerability description:
```
_traverse_atoms parses MP4 atom sizes with unpack_from and never validates them against the header length. A crafted invalid atom size sends the parser into an infinite loop (variant of GHSA-24cc-9352-h2pg / CVE-2026-104266).
```
Expected spans: 622-622 (semgrep), 605-606 (fix_diff), 608-609 (fix_diff), 610-612 (fix_diff), 614-614 (fix_diff), 618-618 (fix_diff), 621-623 (fix_diff), 626-633 (fix_diff), 636-644 (fix_diff), 647-649 (fix_diff), 652-652 (fix_diff), 668-668 (fix_diff), 672-673 (fix_diff), 676-676 (fix_diff), 679-679 (fix_diff), 681-683 (fix_diff), 689-691 (fix_diff), 707-708 (fix_diff), 716-716 (fix_diff), 718-718 (fix_diff), 725-726 (fix_diff), 728-728 (fix_diff), 738-738 (fix_diff), 741-744 (fix_diff), 760-760 (fix_diff), 765-765 (fix_diff), 767-767 (fix_diff), 771-771 (fix_diff)
Numbered vuln window:
```
   480  class _MP4(TinyTag):
   481      """MP4 Audio Parser.
   482  
   483      https://developer.apple.com/library/mac/documentation/QuickTime/QTFF/Metadata/Metadata.html
   484      https://developer.apple.com/library/mac/documentation/QuickTime/QTFF/QTFFChap2/qtff2.html
   485      """
   486  
   487      _CUSTOM_FIELD_NAME_MAPPING = {
   488          'artists': 'artist',
   489          'conductor': 'other.conductor',
   490          'discsubtitle': 'other.set_subtitle',
   491          'initialkey': 'other.initial_key',
   492          'isrc': 'other.isrc',
   493          'language': 'other.language',
   494          'lyricist': 'other.lyricist',
   495          'media': 'other.media',
   496          'website': 'other.url',
   497          'license': 'other.license',
   498          'barcode': 'other.barcode',
   499          'catalognumber': 'other.catalog_number',
   500      }
   501      _IMAGE_MIME_TYPES = {
   502          12: 'image/gif',
   503          13: 'image/jpeg',
   504          14: 'image/png',
   505          27: 'image/bmp'
   506      }
   507      _UNPACK_FORMATS = {
   508          1: '>b',
   509          2: '>h',
   510          4: '>i',
   511          8: '>q'
   512      }
   513      _VERSIONED_ATOMS = {b'meta', b'stsd'}  # those have an extra 4 byte header
   514      _FLAGGED_ATOMS = {b'stsd'}  # these also have an extra 4 byte header
   515      _ILST_PATH = [b'ftyp', b'moov', b'udta', b'meta', b'ilst']
   516  
   517      _audio_data_tree: _DataTreeDict | None = None
   518      _meta_data_tree: _DataTreeDict | None = None
   519      _combined_tree: _DataTreeDict | None = None
   520  
   521      def _parse(self, fh: BinaryIO) -> None:
   522          # The parser tree: Each key is an atom name which is traversed if
   523          # existing. Leaves of the parser tree are callables which receive
   524          # the atom data. Callables return {fieldname: value} which is updates
   525          # the TinyTag.
   526          tree = {}
   527          if self._parse_duration and self._parse_tags:
   528              tree = self._build_combined_tree()
   529          elif self._parse_duration:
   530              tree = self._build_audio_data_tree()
   531          elif self._parse_tags:
   532              tree = self._build_meta_data_tree()
   533          self._traverse_atoms(fh, path=tree)
   534          self._duration_parsed = self._parse_duration
   535          self._tags_parsed = self._parse_tags
   536  
   537      @classmethod
   538      def _build_audio_data_tree(cls) -> _DataTreeDict:
   539          if cls._audio_data_tree is None:
   540              # https://developer.apple.com/library/mac/documentation/QuickTime/QTFF/QTFFChap3/qtff3.html
   541              cls._audio_data_tree = {
   542                  b'moov': {
   543                      b'mvhd': _MP4._parse_mvhd,
   544                      b'trak': {b'mdia': {b"minf": {b"stbl": {b"stsd": {
   545                          b'mp4a': _MP4._parse_mp4a,
   546                          b'alac': _MP4._parse_alac
   547                      }}}}}
   548                  }
   549              }
   550          return cls._audio_data_tree
   551  
   552      @classmethod
   553      def _build_meta_data_tree(cls) -> _DataTreeDict:
   554          if cls._meta_data_tree is None:
   555              cls._meta_data_tree = {b'moov': {b'udta': {b'meta': {b'ilst': {
   556                  # http://atomicparsley.sourceforge.net/mpeg-4files.html
   557                  # https://metacpan.org/dist/Image-ExifTool/source/lib/Image/ExifTool/QuickTime.pm#L3093
   558                  b'\xA9ART': {b'data': _MP4._data_parser('artist')},
   559                  b'\xA9alb': {b'data': _MP4._data_parser('album')},
   560                  b'\xA9cmt': {b'data': _MP4._data_parser('comment')},
   561                  b'\xA9com': {b'data': _MP4._data_parser('composer')},
   562                  b'\xA9con': {b'data': _MP4._data_parser('other.conductor')},
   563                  b'\xA9day': {b'data': _MP4._data_parser('year')},
   564                  b'\xA9des': {b'data': _MP4._data_parser('other.description')},
   565                  b'\xA9dir': {b'data': _MP4._data_parser('other.director')},
   566                  b'\xA9gen': {b'data': _MP4._data_parser('genre')},
   567                  b'\xA9grp': {b'data': _MP4._data_parser('other.grouping')},
   568                  b'\xA9lyr': {b'data': _MP4._data_parser('other.lyrics')},
   569                  b'\xA9mvc': {
   570                      b'data': _MP4._data_parser('other.movement_total')
   571                  },
   572                  b'\xA9mvi': {b'data': _MP4._data_parser('other.movement')},
   573                  b'\xA9mvn': {
   574                      b'data': _MP4._data_parser('other.movement_name')
   575                  },
   576                  b'\xA9nam': {b'data': _MP4._data_parser('title')},
   577                  b'\xA9pub': {b'data': _MP4._data_parser('other.publisher')},
   578                  b'\xA9too': {b'data': _MP4._data_parser('other.encoded_by')},
   579                  b'\xA9wrk': {b'data': _MP4._data_parser('other.work')},
   580                  b'\xA9wrt': {b'data': _MP4._data_parser('composer')},
   581                  b'aART': {b'data': _MP4._data_parser('albumartist')},
   582                  b'cprt': {b'data': _MP4._data_parser('other.copyright')},
   583                  b'desc': {b'data': _MP4._data_parser('other.description')},
   584                  b'disk': {b'data': _MP4._nums_parser('disc', 'disc_total')},
   585                  b'gnre': {b'data': _MP4._parse_id3v1_genre},
   586                  b'shwm': {b'data': _MP4._data_parser('other.show_movement')},
   587                  b'trkn': {b'data': _MP4._nums_parser('track', 'track_total')},
   588                  b'tmpo': {b'data': _MP4._data_parser('other.bpm')},
   589                  b'covr': {b'data': _MP4._parse_cover_image},
   590                  b'----': _MP4._parse_custom_field,
   591              }}}}, b'uuid': _MP4._parse_uuid}
   592          return cls._meta_data_tree
   593  
   594      @classmethod
   595      def _build_combined_tree(cls) -> _DataTreeDict:
   596          if cls._combined_tree is None:
   597              cls._combined_tree = result = dict(cls._build_audio_data_tree())
   598              for key, value in cls._build_meta_data_tree().items():
   599                  current = result.get(key)
   600                  if isinstance(current, dict) and isinstance(value, dict):
   601                      result[key] = {**current, **value}
   602                  else:
   603                      result[key] = value
   604          return cls._combined_tree
   605  
   606      def _traverse_atoms(self,
   607                          fh: BinaryIO,
   608                          path: _DataTreeDict,
   609                          stop_pos: int | None = None,
   610                          curr_path: list[bytes] | None = None) -> None:
   611          header_len = ext_size_len = 8
   612          atom_header = fh.read(header_len)
   613          if curr_path is None:
   614              atom_type = atom_header[4:]
   615              # Should be safe enough for a quick header check. Newer MP4
   616              # files tend to start with an 'ftyp' atom. Older files don't,
   617              # but their initial atom type only seem to use ASCII chars.
   618              if len(atom_type) != 4 or not atom_type.isascii():
   619                  raise ParseError('Invalid MP4 header')
   620              self.mime_type = 'audio/mp4'
   621          while len(atom_header) == header_len:
   622              atom_size = unpack_from('>I', atom_header)[0]
   623              atom_type = atom_header[4:]
   624              if curr_path is None:
   625                  curr_path = [atom_type]
   626              if atom_size == 1:  # 64-bit size
   627                  ext_size_header = fh.read(ext_size_len)
   628                  if len(ext_size_header) == ext_size_len:
   629                      atom_size = unpack('>Q', ext_size_header)[0] - ext_size_len
   630              atom_size -= header_len
   631              if atom_size <= 0:  # empty atom, jump to next one
   632                  atom_header = fh.read(header_len)
   633                  continue
   634              if _DEBUG:
   635                  print(f'{" " * 4 * len(curr_path)} '
   636                        f'pos: {fh.tell() - header_len} '
   637                        f'atom: {atom_type!r} len: {atom_size + header_len}')
   638              if atom_type in self._VERSIONED_ATOMS:  # jump atom version for now
   639                  fh.seek(4, SEEK_CUR)
   640                  atom_size -= 4
   641              if atom_type in self._FLAGGED_ATOMS:  # jump atom flags for now
   642                  fh.seek(4, SEEK_CUR)
   643                  atom_size -= 4
   644              sub_path = path.get(atom_type, None)
   645              # if the path leaf is a dict, traverse deeper into the tree:
   646              if isinstance(sub_path, dict):
   647                  atom_end_pos = fh.tell() + atom_size
   648                  self._traverse_atoms(fh, path=sub_path, stop_pos=atom_end_pos,
   649                                       curr_path=curr_path + [atom_type])
   650              # if the path-leaf is a callable, call it on the atom data
   651              elif callable(sub_path):
   652                  for fieldname, value in sub_path(fh.read(atom_size)):
   653                      if _DEBUG:
   654                          print(' ' * 4 * len(curr_path), 'FIELD: ', fieldname)
   655                      if isinstance(value, Image):
   656                          if self._load_image:
   657                              # pylint: disable=protected-access
   658                              self.images._set_field(fieldname, value)
   659                      elif isinstance(value, list):
   660                          for subval in value:
   661                              self._set_field(fieldname, subval)
   662                      elif fieldname == 'codec':
   663                          self.mime_type = f'audio/mp4; codecs="{value}"'
   664                      else:
   665                          self._set_field(fieldname, value)
   666              # unknown data atom, try to parse it
   667              elif curr_path == self._ILST_PATH:
   668                  atom_end_pos = fh.tell() + atom_size
   669                  field_name = (
   670                      self._OTHER_PREFIX + atom_type.decode('latin-1').lower()
   671                  )
   672                  fh.seek(-header_len, SEEK_CUR)
   673                  self._traverse_atoms(
   674                      fh,
   675                      path={atom_type: {b'data': self._data_parser(field_name)}},
   676                      stop_pos=atom_end_pos, curr_path=curr_path + [atom_type])
   677              # if no action was specified using dict or callable, jump over atom
   678              else:
   679                  fh.seek(atom_size, SEEK_CUR)
   680              # check if we have reached the end of this branch:
   681              if stop_pos and fh.tell() >= stop_pos:
   682                  return  # return to parent (next parent node in tree)
   683              atom_header = fh.read(header_len)  # read next atom
   684  
   685      @classmethod
   686      def _data_parser(
   687          cls, fieldname: str
   688      ) -> Callable[[bytes], Iterator[tuple[str, str]]]:
   689          def _parse_data_atom(data_atom: bytes) -> Iterator[tuple[str, str]]:
   690              data_type = unpack_from('>I', data_atom)[0]
   691              data = data_atom[8:]
   692              value = ""
   693              if data_type == 1:     # UTF-8 string
   694                  value = data.decode('utf-8', 'replace')
   695              elif data_type == 21:  # BE signed integer
   696                  fmts = cls._UNPACK_FORMATS
   697                  data_len = len(data)
   698                  if data_len in fmts:
   699                      value = str(unpack(fmts[data_len], data)[0])
   700              yield fieldname, value
   701          return _parse_data_atom
   702  
   703      @classmethod
   704      def _nums_parser(
   705          cls, fieldname1: str, fieldname2: str
   706      ) -> Callable[[bytes], Iterator[tuple[str, int]]]:
   707          def _parse_nums(data_atom: bytes) -> Iterator[tuple[str, int]]:
   708              number_data = data_atom[8:14]
   709              numbers = unpack('>3H', number_data)
   710              # for some reason the first number is always irrelevant.
   711              yield fieldname1, numbers[1]
   712              yield fieldname2, numbers[2]
   713          return _parse_nums
   714  
   715      @classmethod
   716      def _parse_id3v1_genre(cls, data_atom: bytes) -> Iterator[tuple[str, str]]:
   717          # dunno why genre is offset by -1 but that's how mutagen does it
   718          idx = unpack_from('>H', data_atom, 8)[0] - 1
   719          # pylint: disable=protected-access
   720          if idx < len(_ID3._ID3V1_GENRES):
   721              yield 'genre', _ID3._ID3V1_GENRES[idx]
   722  
   723      @classmethod
   724      def _parse_cover_image(cls,
   725                             data_atom: bytes) -> Iterator[tuple[str, Image]]:
   726          data_type = unpack_from('>I', data_atom)[0]
   727          image_name = 'front_cover'
   728          image_data = data_atom[8:]
   729          image = Image(
   730              image_name, len(image_data), image_data,
   731              cls._IMAGE_MIME_TYPES.get(data_type))
   732          yield image_name, image
   733  
   734      @classmethod
   735      def _parse_custom_field(cls,
   736                              data: bytes) -> Iterator[tuple[str, list[str]]]:
   737          fh = BytesIO(data)
   738          header_len = 8
   739          field_name = None
   740          values = []
   741          atom_header = fh.read(header_len)
   742          while len(atom_header) == header_len:
   743              atom_size = unpack_from('>I', atom_header)[0] - header_len
   744              atom_type = atom_header[4:]
   745              if atom_type == b'name':
   746                  atom_value = fh.read(atom_size)[4:].lower()
   747                  field_name = atom_value.decode('utf-8', 'replace')
   748                  # pylint: disable=protected-access
   749                  field_name = cls._CUSTOM_FIELD_NAME_MAPPING.get(
   750                      field_name, cls._OTHER_PREFIX + field_name)
   751              elif atom_type == b'data' and field_name:
   752                  data_atom = fh.read(atom_size)
   753                  parser = cls._data_parser(field_name)
   754                  atom_values = parser(data_atom)
   755                  for _field_name, value in atom_values:
   756                      values.append(value)
   757                      break
   758              else:
   759                  fh.seek(atom_size, SEEK_CUR)
   760              atom_header = fh.read(header_len)  # read next atom
   761          if field_name and values:
   762              yield field_name, values
   763  
   764      @classmethod
   765      def _parse_uuid(cls, data_atom: bytes) -> Iterator[tuple[str, str]]:
   766          uuid_len = 16
   767          uuid = data_atom[:uuid_len]
   768          if uuid == (
   769              b'\xBE\x7A\xCF\xCB\x97\xA9\x42\xE8\x9C\x71\x99\x94\x91\xE3\xAF\xAC'
   770          ):
   771              yield 'other.xmp', data_atom[uuid_len:].decode('utf-8', 'replace')
   772  
   773      @classmethod
   774      def _parse_mp4a(cls, data: bytes) -> Iterator[tuple[str, str | float]]:
   775          # this atom also contains the esds atom:
   776          # https://ffmpeg.org/doxygen/0.6/mov_8c-source.html
   777          # http://xhelmboyx.tripod.com/formats/mp4-layout.txt
   778          # http://sasperger.tistory.com/103
   779  
   780          # jump over version and flags
   781          channels = unpack_from('>H', data, 16)[0]
   782          yield 'channels', channels
   783          # jump over bit_depth, QT compr id & pkt size
   784          sr = unpack_from('>I', data, 22)[0]
   785          yield 'samplerate', sr
   786  
   787          # ES Description Atom
   788          def _read_descriptor_size(data: bytes, offset: int) -> tuple[int, int]:
   789              size = 0
   790              continuation = 1 << 7
   791              for _i in range(4):
   792                  byte = data[offset]
   793                  offset += 1
   794                  size = (size << 7) | (byte & ((1 << 7) - 1))
   795                  if not (byte & continuation):
   796                      break
   797              return size, offset
   798  
   799          offset = 36 + 5   # jump over version, flags and tag
   800  
   801          # ES Descriptor
   802          _size, offset = _read_descriptor_size(data, offset)
   803          offset += 4   # jump over ES id, flags and tag
   804  
   805          # Decoder Config Descriptor
   806          _size, offset = _read_descriptor_size(data, offset)
   807          object_type = data[offset]
   808          codec = f'mp4a.{object_type:X}'
   809          offset += 9
   810          avg_br = unpack_from('>I', data, offset)[0]
   811          if avg_br > 0:
   812              yield 'bitrate', avg_br / 1000  # kbit/s
   813          offset += 5
   814  
   815          # Decoder Specific Info
   816          _size, offset = _read_descriptor_size(data, offset)
   817          first = data[offset]
   818          second = data[offset + 1]
   819          audio_object_type = first >> 3
   820          if audio_object_type == 31:
   821              # Read extended value
   822              extended = ((first & 0x07) << 3) | (second >> 5)
   823              audio_object_type = 32 + extended
   824          if audio_object_type:
   825              codec += f'.{audio_object_type}'
   826          yield 'codec', codec
   827  
   828      @classmethod
   829      def _parse_alac(cls, data: bytes) -> Iterator[tuple[str, str | int]]:
   830          # https://github.com/macosforge/alac/blob/master/ALACMagicCookieDescription.txt
   831          yield 'codec', 'alac'
   832          bitdepth = data[45]
   833          yield 'bitdepth', bitdepth
   834          channels = data[49]
   835          yield 'channels', channels
   836          avg_br, sr = unpack_from('>II', data, 56)
   837          yield 'samplerate', sr
   838          avg_br /= 1000  # kbit/s
   839          yield 'bitrate', avg_br
   840  
   841      @classmethod
   842      def _parse_mvhd(cls, data: bytes) -> Iterator[tuple[str, float]]:
   843          # http://stackoverflow.com/a/3639993/1191373
   844          version = data[0]
   845          # jump over flags, create & mod times
   846          if version == 0:  # uses 32 bit integers for timestamps
   847              time_scale, duration = unpack_from('>II', data, 12)
   848          else:  # version == 1:  # uses 64-bit integers for timestamps
   849              time_scale, duration = unpack_from('>IQ', data, 20)
   850          yield 'duration', duration / time_scale
```
Vuln review text:
````
Security review of the MP4 parser in `tinytag.py` found several denial-of-service issues in untrusted-file parsing. No memory-corruption or injection bugs showed up in this Python code.

**1. Infinite loop (CWE-835)**
File: `tinytag.py`, lines 743 and 759
```
atom_size = unpack_from('>I', atom_header)[0] - header_len
```
```
fh.seek(atom_size, SEEK_CUR)
```
`_parse_custom_field` subtracts the 8-byte header from the attacker-controlled size and, for any inner atom that is not `name`/`data`, seeks by that delta. A size of 0 yields `atom_size == -8`, so `seek(-8, SEEK_CUR)` lands back on the same header and the `while` loop never ends. Sizes 1–7 seek backward as well and can be cycled. This runs on a normal `----` (freeform) atom while parsing tags. Negative sizes on the `name`/`data` branches hit `fh.read(atom_size)` and raise `ValueError` instead.

**2. Divide by zero (CWE-369)**
File: `tinytag.py`, line 850
```
yield 'duration', duration / time_scale
```
`time_scale` comes from the `mvhd` atom and is not checked. A zero timescale raises `ZeroDivisionError`. Both the version-0 and version-1 branches use this expression.

**3. Unbounded read/seek from atom size (CWE-400 / CWE-789)**
File: `tinytag.py`, line 652
```
for fieldname, value in sub_path(fh.read(atom_size)):
```
File: `tinytag.py`, line 679
```
fh.seek(atom_size, SEEK_CUR)
```
Payload length is taken from the 32-bit size, or from the 64-bit extended size when the size field is 1, and is never capped against the remaining input or a maximum. `read(atom_size)` can try to allocate up to ~4 GiB (32-bit size) or far more (64-bit size). `seek` with an offset that does not fit in a signed 64-bit `off_t` raises `OverflowError`. Either one is an unhandled crash on a crafted atom (`mdat`, `free`, `mvhd`, `mp4a`, and so on).

**4. Missing bounds checks before unpack/index (CWE-20 / CWE-125)**
Short or truncated atoms are indexed or unpacked with fixed offsets and no length check, so malformed input raises `struct.error` or `IndexError` instead of `ParseError`.

File: `tinytag.py`, line 690
```
data_type = unpack_from('>I', data_atom)[0]
```
File: `tinytag.py`, line 709
```
numbers = unpack('>3H', number_data)
```
File: `tinytag.py`, line 781
```
channels = unpack_from('>H', data, 16)[0]
```
File: `tinytag.py`, line 792
```
byte = data[offset]
```
File: `tinytag.py`, line 818
```
second = data[offset + 1]
```
File: `tinytag.py`, line 832
```
bitdepth = data[45]
```
Same pattern at lines 726, 784, 807, 817, 834, 836, 844, 847, and 849. `_read_descriptor_size` only caps its own loop at 4 bytes; later uses of `offset` are unchecked.

**5. Negative genre index (CWE-129)** — low
File: `tinytag.py`, lines 718 and 721
```
idx = unpack_from('>H', data_atom, 8)[0] - 1
```
```
yield 'genre', _ID3._ID3V1_GENRES[idx]
```
The check is only `idx < len(...)`. A stored value of 0 makes `idx == -1`, which passes that test and returns the last genre via Python’s negative indexing. Incorrect metadata, not a crash.
````
Vuln judge parsed JSON:
```
{
  "cited_ranges": [],
  "rationale": "The ground truth is an infinite loop in _traverse_atoms (lines 606-683) caused by atom sizes that are never validated against the header length. The review's infinite-loop finding (#1) targets _parse_custom_field at lines 743 and 759, which is a different function with a similar pattern but is not the _traverse_atoms bug. Finding #3 cites lines 652 and 679 in _traverse_atoms, but it describes unbounded read/seek memory and overflow, not an infinite loop from an invalid size. _traverse_atoms already handles atom_size <= 0 at line 631, so no finding describes the reference weakness.",
  "verdict_class_match": false
}
```
Harness verdict: MISS
Fixed review text:
```
The MP4 parser has four security issues, all triggered by a crafted file. They are denial-of-service and parser-integrity bugs, not memory corruption.

**1. tinytag.py:874 — CWE-369 (Divide By Zero)**
`yield 'duration', duration / time_scale`
`time_scale` comes from the `mvhd` atom (`>I` or `>Q`) and is not checked. A zero timescale raises `ZeroDivisionError` and aborts parsing.

**2. tinytag.py:660 — CWE-191 (Integer Underflow)**
`if atom_type in self._FLAGGED_ATOMS:  # skip atom flags`
`stsd` is in both `_VERSIONED_ATOMS` and `_FLAGGED_ATOMS`, and the second skip is not an `elif` and does not recheck `atom_size >= 4`. A payload of 4–7 bytes makes `atom_size` negative (lines 659–662). That negative value is then used as `stop_pos=curr_pos + atom_size` (line 669) or `fh.seek(atom_size, SEEK_CUR)` (line 705), so the parser seeks backward and no longer honors the container end.

**3. tinytag.py:674 — CWE-770 (Allocation of Resources Without Limits)**
`data = fh.read(atom_size)`
`atom_size` is taken from the file (`>I`, or `>Q` up to 2^64−1 at line 622) with no upper bound. Any leaf that is parsed (`mp4a`, `data`, `covr`, and so on) is buffered in full, so a huge declared atom exhausts memory.

**4. tinytag.py:717 — CWE-20 (Improper Input Validation) / CWE-248 (Uncaught Exception)**
`data_type = unpack_from('>I', data)[0]`
Fixed offsets and `unpack` calls do not check the remaining length, so a short atom raises `IndexError` or `struct.error`. Same pattern at 736, 745, 753, 805, 808, 816, 831, 834, 841, 842, 856, 858, 860, 868, 871, and 873. Example: `byte = data[offset]` (816) and `bitdepth = data[45]` (856).
```
Fixed judge parsed JSON:
```
{
  "cited_ranges": [],
  "rationale": "The patched vulnerability is the missing validation of atom sizes against the header length, which led to an infinite loop. The patched code now checks this at line 623 (`atom_size < header_size`). The review does not claim that this check is missing or insufficient. It reports four other issues: divide by zero, a negative atom_size from the stsd double skip, unbounded reads, and short-data parse errors. Issue 2 does touch atom_size handling and mentions seeking backward, but it concerns the version/flags skips at lines 659-662, not the header-size validation. It is a different bug, so this does not count as reporting the patched vulnerability.",
  "reported_patched_vuln": false
}
```
fixed_clean: true

Human verdict (HIT/PARTIAL/MISS):
Human fixed side (clean/re-reported):
Agree with harness (yes/no):
Notes:

## Case 3: GHSA-637c-6jxx-4rwm (run 20261020T145119Z-reviewer-a-3aec9d76)
Case id: GHSA-637c-6jxx-4rwm
Guard class: allowlist-denylist
Vulnerability description:
```
Vault authentication silently defaults to the operator's Kubernetes service-account token file. A leaked token grants Kubernetes API access from tenant-controlled Vault destinations (variant of GHSA-637c-6jxx-4rwm / CVE-2026-77524).
```
Expected spans: 126-126 (semgrep), 22-23 (fix_diff), 33-33 (fix_diff), 55-56 (fix_diff), 71-71 (fix_diff), 97-97 (fix_diff), 99-100 (fix_diff), 108-108 (fix_diff), 122-130 (fix_diff), 132-140 (fix_diff), 147-148 (fix_diff), 156-157 (fix_diff)
Numbered vuln window:
```
    19  import (
    20  	"context"
    21  	"errors"
    22  	"fmt"
    23  	"strings"
    24  
    25  	"github.com/go-logr/logr"
    26  	vaultapi "github.com/hashicorp/vault/api"
        ... (lines 27-29 omitted)
    30  )
    31  
    32  const (
    33  	serviceAccountTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    34  )
    35  
    36  // HashicorpVaultHandler is a specification of HashiCorp Vault
        ... (lines 37-54 omitted)
    55  func (vh *HashicorpVaultHandler) Initialize(logger logr.Logger) error {
    56  	config := vaultapi.DefaultConfig()
    57  	client, err := vaultapi.NewClient(config)
    58  	if err != nil {
    59  		return err
    60  	}
    61  
    62  	err = client.SetAddress(vh.vault.Address)
    63  	if err != nil {
    64  		return err
    65  	}
    66  
    67  	if len(vh.vault.Namespace) > 0 {
    68  		client.SetNamespace(vh.vault.Namespace)
    69  	}
    70  
    71  	token, err := vh.token(client)
    72  	if err != nil {
    73  		return err
    74  	}
    75  
    76  	if len(token) > 0 {
    77  		client.SetToken(token)
    78  	}
    79  
    80  	lookup, err := client.Auth().Token().LookupSelf()
    81  	// If token is not valid so get out of here early
    82  	if err != nil {
    83  		return err
    84  	}
    85  
    86  	vh.client = client
    87  
    88  	if renew, ok := lookup.Data["renewable"].(bool); ok && renew {
    89  		vh.stopCh = make(chan struct{})
    90  		go vh.renewToken(logger)
    91  	}
    92  
    93  	return nil
    94  }
        ... (lines 95-96 omitted)
    97  func (vh *HashicorpVaultHandler) token(client *vaultapi.Client) (string, error) {
    98  	var token string
    99  	var jwt []byte
   100  	var err error
   101  
   102  	switch vh.vault.Authentication {
   103  	case kedav1alpha1.VaultAuthenticationToken:
   104  		// Got token from VAULT_TOKEN env variable
   105  		switch {
   106  		case len(client.Token()) > 0:
   107  			break
   108  		case len(vh.vault.Credential.Token) > 0:
   109  			token = vh.vault.Credential.Token
   110  		default:
   111  			return token, errors.New("could not get Vault token")
   112  		}
   113  	case kedav1alpha1.VaultAuthenticationKubernetes:
   114  		if len(vh.vault.Mount) == 0 {
   115  			return token, errors.New("auth mount not in config")
   116  		}
   117  
   118  		if len(vh.vault.Role) == 0 {
   119  			return token, errors.New("k8s role not in config")
   120  		}
   121  
   122  		if vh.vault.Credential == nil {
   123  			defaultCred := kedav1alpha1.Credential{
   124  				ServiceAccount: serviceAccountTokenFile,
   125  			}
   126  			vh.vault.Credential = &defaultCred
   127  		}
   128  
   129  		if vh.vault.Credential.ServiceAccountName == "" && vh.vault.Credential.ServiceAccount == "" {
   130  			return token, errors.New("k8s SA file not in config or serviceAccountName not supplied")
   131  		}
   132  
   133  		if vh.vault.Credential.ServiceAccountName != "" {
   134  			jwt = []byte(GenerateBoundServiceAccountToken(context.Background(), vh.vault.Credential.ServiceAccountName, vh.namespace, vh.acs))
   135  		} else if len(vh.vault.Credential.ServiceAccount) != 0 {
   136  			// Get the JWT from POD
   137  			jwt, err = readKubernetesServiceAccountProjectedToken(vh.vault.Credential.ServiceAccount)
   138  			if err != nil {
   139  				return token, err
   140  			}
   141  		}
   142  
   143  		data := map[string]any{"jwt": string(jwt), "role": vh.vault.Role}
   144  		secret, err := client.Logical().Write(fmt.Sprintf("auth/%s/login", vh.vault.Mount), data)
   145  		if err != nil {
   146  			return token, err
   147  		}
   148  		token = secret.Auth.ClientToken
   149  
   150  	default:
   151  		return token, fmt.Errorf("vault auth method %s is not supported", vh.vault.Authentication)
   152  	}
   153  
   154  	return token, nil
   155  }
   156  
   157  // renewToken takes charge of renewing the vault token
```
Vuln review text:
```
The code has seven security issues. `vh.vault` is treated as untrusted operator input, such as a namespaced custom resource.

1. **Path injection (CWE-22)** at `hashicorpvault_handler.go:144`. The line `secret, err := client.Logical().Write(fmt.Sprintf("auth/%s/login", vh.vault.Mount), data)` interpolates `vh.vault.Mount` into the Vault API path with no allowlist or slash rejection. A value such as `../…` changes which endpoint is written. If the client already carries `VAULT_TOKEN` from `NewClient`, that write is authenticated, and the body includes the Kubernetes JWT.

2. **Arbitrary file read (CWE-22)** at `hashicorpvault_handler.go:137`. The line `jwt, err = readKubernetesServiceAccountProjectedToken(vh.vault.Credential.ServiceAccount)` passes a config-supplied path to a file read. It is not restricted to `/var/run/secrets/kubernetes.io/serviceaccount/token` (the constant at line 33). The bytes are then sent outward as `jwt` at lines 143–144.

3. **SSRF / credential exposure (CWE-918)** at `hashicorpvault_handler.go:62`. The line `err = client.SetAddress(vh.vault.Address)` sets the Vault address from config with no scheme or host allowlist. Later calls (`login`, `LookupSelf`) send the client token and the service-account JWT to that host, including `http://` or an attacker-controlled server.

4. **Confused deputy (CWE-441)** at `hashicorpvault_handler.go:134`. The line `jwt = []byte(GenerateBoundServiceAccountToken(context.Background(), vh.vault.Credential.ServiceAccountName, vh.namespace, vh.acs))` mints a service-account token for a caller-supplied name using the operator’s credentials. This call site does not check that the requester may use that service account.

5. **Authentication-context mix-up (CWE-287)** at `hashicorpvault_handler.go:106`. The line `case len(client.Token()) > 0:` breaks without applying `vh.vault.Credential.Token`. A process-wide `VAULT_TOKEN` loaded by `NewClient` is kept and used for this tenant, so the configured token is ignored and tenants share the operator credential.

6. **Nil dereference (CWE-476)** at `hashicorpvault_handler.go:108`. The line `case len(vh.vault.Credential.Token) > 0:` panics when the authentication method is token, no ambient token is set, and `Credential` is nil. The Kubernetes branch nil-checks `Credential` at line 122, but this branch does not.

7. **Nil dereference (CWE-476)** at `hashicorpvault_handler.go:148`. The line `token = secret.Auth.ClientToken` panics when `Write` returns a nil `secret` or a nil `secret.Auth` with a nil error, which the Vault client can do.
```
Vuln judge parsed JSON:
```
{
  "cited_ranges": [],
  "rationale": "The known vulnerability is that when Credential is nil, lines 122-127 silently default to the operator's Kubernetes service-account token file. A tenant-controlled Vault address can then receive that token. No finding in the review identifies this silent default. Finding 2 concerns arbitrary file read through a config-supplied ServiceAccount path at line 137, which is a different weakness. Finding 3 covers SSRF to an attacker-controlled address at line 62, but it never mentions the default token fallback. Finding 6 notes the nil Credential only in the token branch, and it mentions the nil check at line 122 without identifying the default as a vulnerability. So no finding matches.",
  "verdict_class_match": false
}
```
Harness verdict: MISS
Fixed review text:
```
Review of `hashicorpvault_handler.go` found several security issues. Line numbers refer to that file.

### 1. Path injection in Vault login path
- **File/line:** `hashicorpvault_handler.go:136`
- **Class:** CWE-22 (path traversal) / CWE-88 (argument injection)
- **Line:** `secret, err := client.Logical().Write(fmt.Sprintf("auth/%s/login", vh.vault.Mount), data)`

`vh.vault.Mount` is only checked for non-empty (line 119) and is interpolated into the API path with no allowlist, `PathEscape`, or rejection of `/`, `..`, `?`, or `#`. A caller who can set the mount can shift the `Write` off `auth/<mount>/login` onto another Vault path.

### 2. Attacker-controlled token file path, forwarded to Vault
- **File/line:** `hashicorpvault_handler.go:164` (read at 177; legacy bypass at 181–182; send at 135–136)
- **Class:** CWE-73 (external control of file name/path) / CWE-200 (sensitive data exposure)
- **Lines:**
  - `path = credential.ServiceAccount`
  - `token, err := readKubernetesServiceAccountProjectedToken(path)`
  - `if legacy { return token, nil }`
  - `data := map[string]any{"jwt": string(jwt), "role": vh.vault.Role}`

`credential.ServiceAccount` replaces the configured token path and is passed to the reader with no confinement to an expected token directory. In legacy mode the bytes are returned with no audience check and later posted to Vault as `jwt`. That is an arbitrary read of operator-pod files, and the contents are sent to the configured Vault (which may be caller-influenced; see finding 4).

### 3. Audience allowlist skipped for named service accounts
- **File/line:** `hashicorpvault_handler.go:161–162`
- **Class:** CWE-693 (protection mechanism failure) / CWE-441 (confused deputy)
- **Line:** `token, err := GenerateBoundServiceAccountToken(ctx, credential.ServiceAccountName, vh.namespace, vh.acs)`

This branch returns before `validateK8sSATokenAudiences` (lines 184–186). File-based tokens are audience-checked in non-legacy mode; tokens minted for a caller-supplied `ServiceAccountName` are not. The operator then sends that token to Vault (lines 135–136). There is no visible check that the requesting user may impersonate that service account.

### 4. Operator Kubernetes token sent to Vault in legacy mode
- **File/line:** `hashicorpvault_handler.go:157` (constant at 35; unvalidated return at 181–182; send at 135–136)
- **Class:** CWE-522 (insufficiently protected credentials) / CWE-200
- **Line:** `path = serviceAccountTokenFile`

In legacy mode the default path is the operator API token (`/var/run/secrets/kubernetes.io/serviceaccount/token`). That credential is submitted to Vault as the Kubernetes JWT. The log at line 132 warns and continues. A Vault destination the caller can influence receives a token that can access the Kubernetes API.

### 5. Outbound allowlist fails open and still sends credentials in warn mode
- **File/line:** `hashicorpvault_handler.go:194–195` and `206–208`
- **Class:** CWE-1188 (insecure default) / CWE-918 (SSRF) / CWE-319 (cleartext credential transmission)
- **Lines:**
  - `case "", outboundPolicyOff: return nil`
  - `logger.Info("Warning: Vault endpoint is outside the allowlist; credentials may be sent to an untrusted destination. ...")` followed by `return nil`

Empty policy and `off` skip destination checks. `warn` logs and still continues, so the Kubernetes JWT and Vault token are sent anyway. `http` is an accepted scheme (line 235), so those credentials can also go out in cleartext. `Initialize` validates the address only through this function (line 59) before `SetAddress` (line 69) and login.

### 6. Allowlist does not cover where the client actually sends data
- **File/line:** `hashicorpvault_handler.go:63–69` and `238`
- **Class:** CWE-601 (unvalidated redirect) / CWE-693
- **Lines:**
  - `config := vaultapi.DefaultConfig()`
  - `err = client.SetAddress(vh.vault.Address)`
  - `return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)`

The check compares scheme and host only. The client is the library default: redirects are not pinned back to the allowlist, and path/query on `vh.vault.Address` are ignored by the comparator but still become the request base. A 307/308 from an allowlisted host, or a base URL whose path is not what the operator allowlisted, can move the JWT or token off the compared host. Hosts are not IDNA-normalized before `EqualFold`, so Unicode-fold equivalents can compare equal while resolving differently.
```
Fixed judge parsed JSON:
```
{
  "cited_ranges": [
    {
      "end": 157,
      "start": 157
    },
    {
      "end": 35,
      "start": 35
    },
    {
      "end": 182,
      "start": 181
    },
    {
      "end": 136,
      "start": 135
    },
    {
      "end": 132,
      "start": 132
    }
  ],
  "rationale": "Finding 4 says the operator's Kubernetes service-account token (serviceAccountTokenFile) is the default path in legacy mode and is sent to a caller-influenced Vault destination as the JWT. That is the ground-truth vulnerability: the operator token is used by default and can leak to tenant-controlled Vault. The review claims this still exists in the patched code, citing lines 157, 35, 181-182 and 135-136. The patched code limits this behaviour to an opt-in legacy mode with a warning, but the review still flags it as a live flaw.",
  "reported_patched_vuln": true
}
```
fixed_clean: false

Human verdict (HIT/PARTIAL/MISS):
Human fixed side (clean/re-reported):
Agree with harness (yes/no):
Notes:

## Case 4: GHSA-74vm-87hj-r66f (run 20261020T160902Z-reviewer-b-e125878d)
Case id: GHSA-74vm-87hj-r66f
Guard class: input-validation
Vulnerability description:
```
decodeValue dereferences the schema parameter (schema.Value) without a nil check. A response-header spec whose content schema is nil causes a nil-pointer panic and crashes the process (variant of GHSA-74vm-87hj-r66f / CVE-2026-100349).
```
Expected spans: 270-363 (semgrep), 272-273 (fix_diff)
Numbered vuln window:
```
   270  func decodeValue(dec valueDecoder, param string, sm *openapi3.SerializationMethod, schema *openapi3.SchemaRef, required bool) (any, bool, error) {
   271  	var found bool
   272  
   273  	if len(schema.Value.AllOf) > 0 {
   274  		var value any
   275  		var err error
   276  		for _, sr := range schema.Value.AllOf {
   277  			var f bool
   278  			value, f, err = decodeValue(dec, param, sm, sr, required)
   279  			found = found || f
   280  			if value == nil || err != nil {
   281  				break
   282  			}
   283  		}
   284  		return value, found, err
   285  	}
   286  
   287  	if len(schema.Value.AnyOf) > 0 {
   288  		for _, sr := range schema.Value.AnyOf {
   289  			value, f, _ := decodeValue(dec, param, sm, sr, required)
   290  			found = found || f
   291  			if value != nil {
   292  				return value, found, nil
   293  			}
   294  		}
   295  		if required {
   296  			return nil, found, fmt.Errorf("decoding anyOf for parameter %q failed", param)
   297  		}
   298  		return nil, found, nil
   299  	}
   300  
   301  	if len(schema.Value.OneOf) > 0 {
   302  		isMatched := 0
   303  		var value any
   304  		for _, sr := range schema.Value.OneOf {
   305  			v, f, _ := decodeValue(dec, param, sm, sr, required)
   306  			found = found || f
   307  			if v != nil {
   308  				value = v
   309  				isMatched++
   310  			}
   311  		}
   312  		if isMatched >= 1 {
   313  			return value, found, nil
   314  		}
   315  		if required {
   316  			return nil, found, fmt.Errorf("decoding oneOf failed: %q is required", param)
   317  		}
   318  		return nil, found, nil
   319  	}
   320  
   321  	if schema.Value.Not != nil {
   322  		// TODO(decode not): handle decoding "not" JSON Schema
   323  		return nil, found, errors.New("not implemented: decoding 'not'")
   324  	}
   325  
   326  	if schema.Value.Type != nil {
   327  		var decodeFn func(param string, sm *openapi3.SerializationMethod, schema *openapi3.SchemaRef) (any, bool, error)
   328  		switch {
   329  		case schema.Value.Type.Is("array"):
   330  			decodeFn = func(param string, sm *openapi3.SerializationMethod, schema *openapi3.SchemaRef) (any, bool, error) {
   331  				res, b, e := dec.DecodeArray(param, sm, schema)
   332  				if len(res) == 0 {
   333  					return nil, b, e
   334  				}
   335  				return res, b, e
   336  			}
   337  		case schema.Value.Type.Is("object"):
   338  			decodeFn = func(param string, sm *openapi3.SerializationMethod, schema *openapi3.SchemaRef) (any, bool, error) {
   339  				return dec.DecodeObject(param, sm, schema)
   340  			}
   341  		default:
   342  			decodeFn = dec.DecodePrimitive
   343  		}
   344  		return decodeFn(param, sm, schema)
   345  	}
   346  	switch vDecoder := dec.(type) {
   347  	case *pathParamDecoder:
   348  		_, found = vDecoder.pathParams[param]
   349  	case *urlValuesDecoder:
   350  		if schema.Value.Pattern != "" {
   351  			return dec.DecodePrimitive(param, sm, schema)
   352  		}
   353  		_, found = vDecoder.values[param]
   354  	case *headerParamDecoder:
   355  		_, found = vDecoder.header[http.CanonicalHeaderKey(param)]
   356  	case *cookieParamDecoder:
   357  		_, err := vDecoder.req.Cookie(param)
   358  		found = err != http.ErrNoCookie
   359  	default:
   360  		return nil, found, errors.New("unsupported decoder")
   361  	}
   362  	return nil, found, nil
   363  }
```
Vuln review text:
```
Here is the review of the provided code for security vulnerabilities:

### 1. Improper Input Validation (Validation Bypass)
* **File:** `req_resp_decoder.go`
* **Line:** 312
* **Vulnerability Class:** Improper Input Validation (CWE-20)
* **Quote:** `if isMatched >= 1 {`

**Description:** 
According to the OpenAPI and JSON Schema specifications, the `oneOf` keyword requires that the given data must successfully validate against **exactly one** of the provided subschemas. By checking `if isMatched >= 1`, the code accepts payloads that match multiple schemas. This is a validation bypass that allows malformed or ambiguous data to pass through the decoder, which could lead to unexpected behavior or vulnerabilities in downstream components that expect strict `oneOf` enforcement. The condition should be `if isMatched == 1`.

### 2. Nil Pointer Dereference (Denial of Service)
* **File:** `req_resp_decoder.go`
* **Line:** 273
* **Vulnerability Class:** Nil Pointer Dereference (CWE-476) / Denial of Service
* **Quote:** `if len(schema.Value.AllOf) > 0 {`

**Description:** 
The function accesses `schema.Value.AllOf` without first checking if `schema` or `schema.Value` is `nil`. In the `kin-openapi/openapi3` library, a `SchemaRef` represents either an inline schema or a reference (`$ref`). If the schema is an unresolved reference, `schema.Value` will be `nil`. If an attacker can supply a malicious OpenAPI specification (e.g., in dynamic API gateways or Swagger UI backends) or if the application fails to resolve all references at startup, processing a request against this schema will cause a runtime panic, leading to a Denial of Service (DoS). 

*(Note: This nil pointer vulnerability also cascades to lines 287, 301, 321, and 326 where `schema.Value` is accessed directly).*
```
Vuln judge parsed JSON:
```
{
  "cited_ranges": [
    {
      "end": 273,
      "start": 273
    }
  ],
  "rationale": "Finding 2 reports that decodeValue dereferences schema.Value (line 273) with no nil check on schema or schema.Value, causing a nil-pointer panic and DoS. That is the same missing guard and weakness as the known vulnerability. The review's trigger scenario (an unresolved $ref or malicious spec) differs slightly from the response-header content schema in the ground truth, but the root cause is identical. Finding 1 (the oneOf >= 1 check) is a different bug and is ignored.",
  "verdict_class_match": true
}
```
Harness verdict: HIT
Fixed review text:
````
Here is the review of the provided code for security vulnerabilities:

### 1. Validation Bypass (Improper Input Validation)
**File:** `req_resp_decoder.go`
**Line:** 350-367
**Vulnerability Class:** Validation Bypass

**Quote:**
```go
350: 	switch vDecoder := dec.(type) {
351: 	case *pathParamDecoder:
352: 		_, found = vDecoder.pathParams[param]
353: 	case *urlValuesDecoder:
354: 		if schema.Value.Pattern != "" {
355: 			return dec.DecodePrimitive(param, sm, schema)
356: 		}
357: 		_, found = vDecoder.values[param]
358: 	case *headerParamDecoder:
359: 		_, found = vDecoder.header[http.CanonicalHeaderKey(param)]
360: 	case *cookieParamDecoder:
361: 		_, err := vDecoder.req.Cookie(param)
362: 		found = err != http.ErrNoCookie
363: 	default:
364: 		return nil, found, errors.New("unsupported decoder")
365: 	}
366: 	return nil, found, nil
367: }
```

**Description:**
When decoding parameters (such as query, header, or cookie parameters) using a schema that does not explicitly define a `type` (which is perfectly valid in OpenAPI 3.1 and JSON Schema), the `decodeValue` function falls through to the default switch statement. For these decoders, it merely checks if the parameter is present and returns `nil` for the value, instead of extracting the actual string provided in the request. 

Consequently, the subsequent validation step evaluates `nil` rather than the user's actual input. Because JSON Schema constraints like `maxLength`, `format`, `enum`, and `minLength` only apply when the value is of the corresponding type (e.g., string), validating `nil` will successfully pass. (Note: The author attempted a partial fix for `urlValuesDecoder` by checking `Pattern != ""`, but missed all other string constraints and completely missed headers and cookies). This allows an attacker to completely bypass schema constraints by sending malicious input, which the application may then read directly from the raw request.

### 2. Validation Bypass (Improper Error Handling)
**File:** `req_resp_decoder.go`
**Line:** 293, 309
**Vulnerability Class:** Validation Bypass / Improper Error Handling

**Quote:**
```go
293: 			value, f, _ := decodeValue(dec, param, sm, sr, required)
```
```go
309: 			v, f, _ := decodeValue(dec, param, sm, sr, required)
```

**Description:**
In the `AnyOf` and `OneOf` decoding loops, errors returned by recursive calls to `decodeValue` are explicitly ignored using the blank identifier (`_`). If an attacker provides an invalid value that fails to decode for all specified schemas (for example, providing a non-numeric string for a `type: integer` schema), `decodeValue` will silently swallow the decoding errors and return `nil`. 

If the parameter is optional (`required` is false), the function returns `nil, true, nil`. The subsequent validation step will then validate `nil`. If the schema happens to allow null values (e.g., `anyOf: [{type: integer}, {type: null}]`), the validation will pass. This enables an attacker to bypass input validation and supply malformed data that the application might process, assuming it was safely validated as `null` or empty.
````
Fixed judge parsed JSON:
```
{
  "cited_ranges": [],
  "rationale": "The patched vulnerability is a nil-pointer dereference of schema in decodeValue, now guarded by the nil check at lines 273-275. The review does not claim a missing nil check or a panic. It reports validation bypass for schemas without a type (lines 350-367) and ignored errors in anyOf/oneOf (lines 293, 309). Both are unrelated to the nil schema dereference.",
  "reported_patched_vuln": false
}
```
fixed_clean: true

Human verdict (HIT/PARTIAL/MISS):
Human fixed side (clean/re-reported):
Agree with harness (yes/no):
Notes:

## Case 5: GHSA-2cvf-wqm6-wr9g (run 20261020T160902Z-reviewer-b-e125878d)
Case id: GHSA-2cvf-wqm6-wr9g
Guard class: allowlist-denylist
Vulnerability description:
```
MakeContainer builds a container without first rejecting images that carry the checkpoint annotation. A checkpoint image started via `podman run` disables almost all sandboxing (variant of GHSA-2cvf-wqm6-wr9g / CVE-2026-94603).
```
Expected spans: 33-314 (semgrep), 166-167 (fix_diff)
Numbered vuln window:
```
    33  func MakeContainer(ctx context.Context, rt *libpod.Runtime, s *specgen.SpecGenerator, clone bool, c *libpod.Container) (*specs.Spec, *specgen.SpecGenerator, []libpod.CtrCreateOption, error) {
    34  	rtc, err := rt.GetConfigNoCopy()
    35  	if err != nil {
    36  		return nil, nil, nil, err
    37  	}
    38  
    39  	rlimits, err := specgenutil.GenRlimits(rtc.Ulimits())
    40  	if err != nil {
    41  		return nil, nil, nil, err
    42  	}
    43  	s.Rlimits = append(rlimits, s.Rlimits...)
    44  
    45  	if s.OOMScoreAdj == nil {
    46  		s.OOMScoreAdj = rtc.Containers.OOMScoreAdj
    47  	}
    48  
    49  	if len(rtc.Containers.CgroupConf.Get()) > 0 {
    50  		if s.ResourceLimits == nil {
    51  			s.ResourceLimits = &specs.LinuxResources{}
    52  		}
    53  		if s.ResourceLimits.Unified == nil {
    54  			s.ResourceLimits.Unified = make(map[string]string)
    55  		}
    56  		for _, cgroupConf := range rtc.Containers.CgroupConf.Get() {
    57  			key, val, hasVal := strings.Cut(cgroupConf, "=")
    58  			if !hasVal {
    59  				return nil, nil, nil, fmt.Errorf("CgroupConf %s from containers.conf invalid, must be name=value", cgroupConf)
    60  			}
    61  			if _, ok := s.ResourceLimits.Unified[key]; !ok {
    62  				s.ResourceLimits.Unified[key] = val
    63  			}
    64  		}
    65  	}
    66  
    67  	// If joining a pod, retrieve the pod for use, and its infra container
    68  	var pod *libpod.Pod
    69  	var infra *libpod.Container
    70  	if s.Pod != "" {
    71  		pod, err = rt.LookupPod(s.Pod)
    72  		if err != nil {
    73  			return nil, nil, nil, fmt.Errorf("retrieving pod %s: %w", s.Pod, err)
    74  		}
    75  		if pod.HasInfraContainer() {
    76  			infra, err = pod.InfraContainer()
    77  			if err != nil {
    78  				return nil, nil, nil, err
    79  			}
    80  		}
    81  	}
    82  
    83  	options := []libpod.CtrCreateOption{}
    84  	compatibleOptions := &libpod.InfraInherit{}
    85  	var infraSpec *specs.Spec
    86  	if infra != nil {
    87  		options, infraSpec, compatibleOptions, err = Inherit(infra, s, rt)
    88  		if err != nil {
    89  			return nil, nil, nil, err
    90  		}
    91  	}
    92  
    93  	if err := specgen.FinishThrottleDevices(s); err != nil {
    94  		return nil, nil, nil, err
    95  	}
    96  
    97  	// Set defaults for unset namespaces
    98  	if s.PidNS.IsDefault() {
    99  		defaultNS, err := GetDefaultNamespaceMode("pid", rtc, pod)
   100  		if err != nil {
   101  			return nil, nil, nil, err
   102  		}
   103  		s.PidNS = defaultNS
   104  	}
   105  	if s.IpcNS.IsDefault() {
   106  		defaultNS, err := GetDefaultNamespaceMode("ipc", rtc, pod)
   107  		if err != nil {
   108  			return nil, nil, nil, err
   109  		}
   110  		s.IpcNS = defaultNS
   111  	}
   112  	if s.UtsNS.IsDefault() {
   113  		defaultNS, err := GetDefaultNamespaceMode("uts", rtc, pod)
   114  		if err != nil {
   115  			return nil, nil, nil, err
   116  		}
   117  		s.UtsNS = defaultNS
   118  	}
   119  	if s.UserNS.IsDefault() {
   120  		defaultNS, err := GetDefaultNamespaceMode("user", rtc, pod)
   121  		if err != nil {
   122  			return nil, nil, nil, err
   123  		}
   124  		s.UserNS = defaultNS
   125  		value := string(s.UserNS.NSMode)
   126  		if s.UserNS.Value != "" {
   127  			value = value + ":" + s.UserNS.Value
   128  		}
   129  		mappings, err := util.ParseIDMapping(namespaces.UsernsMode(value), nil, nil, "", "")
   130  		if err != nil {
   131  			return nil, nil, nil, err
   132  		}
   133  		s.IDMappings = mappings
   134  	}
   135  	if s.NetNS.IsDefault() {
   136  		defaultNS, err := GetDefaultNamespaceMode("net", rtc, pod)
   137  		if err != nil {
   138  			return nil, nil, nil, err
   139  		}
   140  		s.NetNS = defaultNS
   141  	}
   142  	if s.CgroupNS.IsDefault() {
   143  		defaultNS, err := GetDefaultNamespaceMode("cgroup", rtc, pod)
   144  		if err != nil {
   145  			return nil, nil, nil, err
   146  		}
   147  		s.CgroupNS = defaultNS
   148  	}
   149  
   150  	if s.ContainerCreateCommand != nil {
   151  		options = append(options, libpod.WithCreateCommand(s.ContainerCreateCommand))
   152  	}
   153  
   154  	if s.Rootfs != "" {
   155  		rootfsOverlay := false
   156  		if s.RootfsOverlay != nil {
   157  			rootfsOverlay = *s.RootfsOverlay
   158  		}
   159  		options = append(options, libpod.WithRootFS(s.Rootfs, rootfsOverlay, s.RootfsMapping))
   160  	}
   161  
   162  	newImage, resolvedImageName, imageData, err := getImageFromSpec(ctx, rt, s)
   163  	if err != nil {
   164  		return nil, nil, nil, err
   165  	}
   166  
   167  	if imageData != nil {
   168  		ociRuntimeVariant := rtc.Engine.ImagePlatformToRuntime(imageData.Os, imageData.Architecture)
   169  		// Don't unnecessarily set and invoke additional libpod
   170  		// option if OCI runtime is still default.
   171  		if ociRuntimeVariant != rtc.Engine.OCIRuntime {
   172  			options = append(options, libpod.WithCtrOCIRuntime(ociRuntimeVariant))
   173  		}
   174  	}
   175  
   176  	if newImage != nil {
   177  		// If the input name changed, we could properly resolve the
   178  		// image. Otherwise, it must have been an ID where we're
   179  		// defaulting to the first name or an empty one if no names are
   180  		// present.
   181  		if strings.HasPrefix(newImage.ID(), resolvedImageName) {
   182  			names := newImage.Names()
   183  			if len(names) > 0 {
   184  				resolvedImageName = names[0]
   185  			}
   186  		}
   187  
   188  		options = append(options, libpod.WithRootFSFromImage(newImage.ID(), resolvedImageName, s.RawImageName))
   189  	}
   190  
   191  	_, err = rt.LookupPod(s.Hostname)
   192  	if len(s.Hostname) > 0 && !s.UtsNS.IsPrivate() && err == nil {
   193  		// ok, we are incorrectly setting the pod as the hostname, let's undo that before validation
   194  		s.Hostname = ""
   195  	}
   196  
   197  	// Set defaults if network info is not provided
   198  	if s.NetNS.IsPrivate() || s.NetNS.IsDefault() {
   199  		if rootless.IsRootless() {
   200  			// when we are rootless we default to default_rootless_network_cmd from containers.conf
   201  			conf, err := rt.GetConfigNoCopy()
   202  			if err != nil {
   203  				return nil, nil, nil, err
   204  			}
   205  			switch conf.Network.DefaultRootlessNetworkCmd {
   206  			case slirp4netns.BinaryName, "":
   207  				s.NetNS.NSMode = specgen.Slirp
   208  			case pasta.BinaryName:
   209  				s.NetNS.NSMode = specgen.Pasta
   210  			default:
   211  				return nil, nil, nil, fmt.Errorf("invalid default_rootless_network_cmd option %q",
   212  					conf.Network.DefaultRootlessNetworkCmd)
   213  			}
   214  		} else {
   215  			// as root default to bridge
   216  			s.NetNS.NSMode = specgen.Bridge
   217  		}
   218  	}
   219  
   220  	if err := s.Validate(); err != nil {
   221  		return nil, nil, nil, fmt.Errorf("invalid config provided: %w", err)
   222  	}
   223  
   224  	finalMounts, finalVolumes, finalOverlays, err := finalizeMounts(ctx, s, rt, rtc, newImage)
   225  	if err != nil {
   226  		return nil, nil, nil, err
   227  	}
   228  
   229  	if len(s.HostUsers) > 0 {
   230  		options = append(options, libpod.WithHostUsers(s.HostUsers))
   231  	}
   232  
   233  	command := makeCommand(s, imageData)
   234  
   235  	infraVol := len(compatibleOptions.Mounts) > 0 || len(compatibleOptions.Volumes) > 0 || len(compatibleOptions.ImageVolumes) > 0 || len(compatibleOptions.OverlayVolumes) > 0
   236  	opts, err := createContainerOptions(rt, s, pod, finalVolumes, finalOverlays, imageData, command, infraVol, *compatibleOptions)
   237  	if err != nil {
   238  		return nil, nil, nil, err
   239  	}
   240  	options = append(options, opts...)
   241  
   242  	if containerType := s.InitContainerType; len(containerType) > 0 {
   243  		options = append(options, libpod.WithInitCtrType(containerType))
   244  	}
   245  	if len(s.Name) > 0 {
   246  		logrus.Debugf("setting container name %s", s.Name)
   247  		options = append(options, libpod.WithName(s.Name))
   248  	}
   249  	if len(s.Devices) > 0 {
   250  		opts = ExtractCDIDevices(s)
   251  		options = append(options, opts...)
   252  	}
   253  	runtimeSpec, err := SpecGenToOCI(ctx, s, rt, rtc, newImage, finalMounts, pod, command, compatibleOptions)
   254  	if err != nil {
   255  		return nil, nil, nil, err
   256  	}
   257  	if clone { // the container fails to start if cloned due to missing Linux spec entries
   258  		if c == nil {
   259  			return nil, nil, nil, errors.New("the given container could not be retrieved")
   260  		}
   261  		conf := c.Config()
   262  		if conf != nil && conf.Spec != nil && conf.Spec.Linux != nil {
   263  			out, err := json.Marshal(conf.Spec.Linux)
   264  			if err != nil {
   265  				return nil, nil, nil, err
   266  			}
   267  			resources := runtimeSpec.Linux.Resources
   268  
   269  			// resources get overwritten similarly to pod inheritance, manually assign here if there is a new value
   270  			marshalRes, err := json.Marshal(resources)
   271  			if err != nil {
   272  				return nil, nil, nil, err
   273  			}
   274  
   275  			err = json.Unmarshal(out, runtimeSpec.Linux)
   276  			if err != nil {
   277  				return nil, nil, nil, err
   278  			}
   279  
   280  			err = json.Unmarshal(marshalRes, runtimeSpec.Linux.Resources)
   281  			if err != nil {
   282  				return nil, nil, nil, err
   283  			}
   284  		}
   285  		if s.ResourceLimits != nil {
   286  			switch {
   287  			case s.ResourceLimits.CPU != nil:
   288  				runtimeSpec.Linux.Resources.CPU = s.ResourceLimits.CPU
   289  			case s.ResourceLimits.Memory != nil:
   290  				runtimeSpec.Linux.Resources.Memory = s.ResourceLimits.Memory
   291  			case s.ResourceLimits.BlockIO != nil:
   292  				runtimeSpec.Linux.Resources.BlockIO = s.ResourceLimits.BlockIO
   293  			case s.ResourceLimits.Devices != nil:
   294  				runtimeSpec.Linux.Resources.Devices = s.ResourceLimits.Devices
   295  			}
   296  		}
   297  	}
   298  	if len(s.HostDeviceList) > 0 {
   299  		options = append(options, libpod.WithHostDevice(s.HostDeviceList))
   300  	}
   301  	if infraSpec != nil && infraSpec.Linux != nil { // if we are inheriting Linux info from a pod...
   302  		// Pass Security annotations
   303  		if len(infraSpec.Annotations[define.InspectAnnotationLabel]) > 0 && len(runtimeSpec.Annotations[define.InspectAnnotationLabel]) == 0 {
   304  			runtimeSpec.Annotations[define.InspectAnnotationLabel] = infraSpec.Annotations[define.InspectAnnotationLabel]
   305  		}
   306  		if len(infraSpec.Annotations[define.InspectAnnotationSeccomp]) > 0 && len(runtimeSpec.Annotations[define.InspectAnnotationSeccomp]) == 0 {
   307  			runtimeSpec.Annotations[define.InspectAnnotationSeccomp] = infraSpec.Annotations[define.InspectAnnotationSeccomp]
   308  		}
   309  		if len(infraSpec.Annotations[define.InspectAnnotationApparmor]) > 0 && len(runtimeSpec.Annotations[define.InspectAnnotationApparmor]) == 0 {
   310  			runtimeSpec.Annotations[define.InspectAnnotationApparmor] = infraSpec.Annotations[define.InspectAnnotationApparmor]
   311  		}
   312  	}
   313  	return runtimeSpec, s, options, err
   314  }
```
Vuln review text:
````
- **File:** `container_create.go`
- **Line:** 286-295
- **Vulnerability Class:** Improper Resource Limitation / Denial of Service
- **Quote:**
```go
			switch {
			case s.ResourceLimits.CPU != nil:
				runtimeSpec.Linux.Resources.CPU = s.ResourceLimits.CPU
			case s.ResourceLimits.Memory != nil:
				runtimeSpec.Linux.Resources.Memory = s.ResourceLimits.Memory
			case s.ResourceLimits.BlockIO != nil:
				runtimeSpec.Linux.Resources.BlockIO = s.ResourceLimits.BlockIO
			case s.ResourceLimits.Devices != nil:
				runtimeSpec.Linux.Resources.Devices = s.ResourceLimits.Devices
			}
```
**Explanation:** In Go, a `switch` statement without an expression evaluates each case in order and executes *only the first one* that evaluates to true, as there is no implicit fallthrough. If a user specifies multiple resource limits (e.g., both CPU and Memory limits), only the first matched limit (CPU) will be applied to the cloned container, and the rest will be silently ignored. This failure to apply intended resource restrictions can allow a container to consume unbounded memory or block I/O, potentially leading to resource exhaustion and a Denial of Service (DoS) on the host system. This should be replaced with independent `if` statements.
````
Vuln judge parsed JSON:
```
{
  "cited_ranges": [],
  "rationale": "The review's only finding is about a switch statement at lines 286-295 that applies just the first matching resource limit when cloning a container. It does not mention the missing check for the checkpoint annotation on images, nor the sandboxing that a checkpoint image would disable. That is a different bug from the known vulnerability.",
  "verdict_class_match": false
}
```
Harness verdict: MISS
Fixed review text:
````
Here is the review of the provided code for security vulnerabilities:

### 1. Improper Resource Limitation (Logic Error)
**File:** `container_create.go`
**Line:** 296-305
**Vulnerability Class:** Improper Resource Limitation / Security Feature Bypass

**Description:**
When cloning a container, the code attempts to apply new resource limits (overrides) from `s.ResourceLimits` to the cloned container's `runtimeSpec.Linux.Resources`. However, it uses a `switch` statement without an expression, which evaluates each case as a boolean and executes only the *first* true case. Because there are no `fallthrough` statements, if a user specifies multiple resource limits (e.g., both CPU and Memory limits), only the first one evaluated (CPU) will be applied, and the rest will be silently ignored. This logic error allows containers to bypass intended resource constraints, potentially leading to resource exhaustion and a Denial of Service (DoS) on the host.

**Quote:**
```go
    296  			switch {
    297  			case s.ResourceLimits.CPU != nil:
    298  				runtimeSpec.Linux.Resources.CPU = s.ResourceLimits.CPU
    299  			case s.ResourceLimits.Memory != nil:
    300  				runtimeSpec.Linux.Resources.Memory = s.ResourceLimits.Memory
    301  			case s.ResourceLimits.BlockIO != nil:
    302  				runtimeSpec.Linux.Resources.BlockIO = s.ResourceLimits.BlockIO
    303  			case s.ResourceLimits.Devices != nil:
    304  				runtimeSpec.Linux.Resources.Devices = s.ResourceLimits.Devices
    305  			}
```

### 2. Denial of Service (Unhandled Nil Pointer in JSON Unmarshal)
**File:** `container_create.go`
**Line:** 290
**Vulnerability Class:** Denial of Service (DoS)

**Description:**
During a container clone, the code marshals the new container's resources into `marshalRes` and then unmarshals them back into `runtimeSpec.Linux.Resources` to merge them with the old container's configuration. If neither the original container nor the new clone configuration has resource limits defined, `runtimeSpec.Linux.Resources` will be `nil`. Passing a typed `nil` pointer directly to `json.Unmarshal` results in an `InvalidUnmarshalError`. This causes the cloning process to fail entirely and reliably for any container without resource limits, leading to a Denial of Service for the clone functionality. 

**Quote:**
```go
    290  			err = json.Unmarshal(marshalRes, runtimeSpec.Linux.Resources)
```
````
Fixed judge parsed JSON:
```
{
  "cited_ranges": [],
  "rationale": "The patched vulnerability is the missing checkpoint-annotation rejection in MakeContainer. The patched code now has that check at lines 167-175. The review does not claim the check is missing. It raises two unrelated issues: the switch logic in the clone resource-limits handling (lines 296-305) and a nil-pointer unmarshal (line 290). Neither concerns the checkpoint annotation.",
  "reported_patched_vuln": false
}
```
fixed_clean: true

Human verdict (HIT/PARTIAL/MISS):
Human fixed side (clean/re-reported):
Agree with harness (yes/no):
Notes:

## Case 6: GHSA-c42q-qvc3-j6vg (run 20261020T160902Z-reviewer-b-e125878d)
Case id: GHSA-c42q-qvc3-j6vg
Guard class: escaping-encoding
Vulnerability description:
```
URL written to href/src without scheme sanitization. Run it through sanitizeUrl first (variant of GHSA-c42q-qvc3-j6vg / CVE-2026-108260).
```
Expected spans: 75-75 (semgrep), 76-76 (semgrep), 1-1 (fix_diff), 75-76 (fix_diff)
Numbered vuln window:
```
     1  import DOMPurify from 'dompurify';
     2  
     3  /**
     4   * @typedef {Object} Node
     5   * @property {string} type
     6   * @property {string} name
     7   * @property {Node[]} children
     8   */
     9  
    10  const TAGS = {
    11    h1: 'h1',
    12    h2: 'h2',
    13    h3: 'h3',
    14    h4: 'h4',
    15    h5: 'h5',
    16    h6: 'h6',
    17    p: 'p',
    18    ol: 'ol',
    19    ul: 'ul',
    20    li: 'li',
    21    lic: 'div',
    22    blockquote: 'blockquote',
    23    img: 'img',
    24    a: 'a',
    25    code_block: 'code',
    26    hr: 'hr',
    27    break: 'br',
    28    table: 'table', // TODO: does not support alignment.
    29    tr: 'tr',
    30    td: 'td',
    31    invalid_markdown: 'pre',
    32    html: 'html',
    33    html_inline: 'html',
    34    mdxJsxTextElement: 'div',
    35    mdxJsxFlowElement: 'div',
    36  };
    37  const MARKS = [
    38    ['bold', 'strong'],
    39    ['italic', 'em'],
    40    ['underline', 'u'],
    41    ['strikethrough', 's'],
    42    ['code', 'code'],
    43    ['highlight', 'mark'],
    44  ];
    45  
    46  /**
    47   * @param {Node} root
    48   * @returns {HTMLElement}
    49   */
    50  function renderRichText(root) {
    51    const container = document.createElement('div');
    52  
    53    for (const block of root.children ?? []) {
    54      container.appendChild(renderNode(block));
    55    }
    56  
    57    return container;
    58  }
    59  
    60  /**
    61   * @param {Node} node
    62   * @returns {HTMLElement}
    63   */
    64  function renderNode(node) {
    65    if (node.type === 'text') return renderText(node);
    66  
    67    if (node.type === 'html' || node.type === 'html_inline') {
    68      return DOMPurify.sanitize(node.value, { RETURN_DOM_FRAGMENT: true });
    69    }
    70  
    71    const tag = TAGS[node.type];
    72    /** @type {HTMLElement} */
    73    const el = document.createElement(tag);
    74  
    75    if (node.url && node.type === 'a') el.href = node.url;
    76    if (node.url && node.type === 'img') el.src = node.url;
    77  
    78    if (node.type === 'mdxJsxTextElement' || node.type === 'mdxJsxFlowElement') {
    79      const override = TinaMarkdown.components[node.name];
    80      if (override) return override(node);
    81      return el;
    82    }
    83  
    84    if (node.type === 'code_block') {
    85      const pre = document.createElement('pre');
    86  
    87      let codeString = '';
    88      if (Array.isArray(node.children)) {
    89        codeString = node.children
    90          .map((line) =>
    91            Array.isArray(line.children)
    92              ? line.children.map((t) => t.text).join('')
    93              : ''
    94          )
    95          .join('\n');
    96      } else if (typeof node.value === 'string') {
    97        codeString = node.value;
    98      }
    99      el.innerText = codeString;
   100      if (node.lang) el.setAttribute('lang', node.lang);
   101  
   102      pre.appendChild(el);
   103      return pre;
   104    }
   105  
   106    if (node.type === 'table') {
   107      const table_body = document.createElement('tbody');
   108      for (const child of node.children ?? []) {
   109        table_body.appendChild(renderNode(child));
   110      }
   111      el.appendChild(table_body);
   112      return el;
   113    }
   114  
   115    for (const child of node.children ?? []) {
   116      el.appendChild(renderNode(child));
   117    }
   118  
   119    return el;
   120  }
   121  
   122  /**
   123   * @param {Node} node
   124   * @returns {Text}
   125   */
   126  function renderText(node) {
   127    let el = document.createTextNode(node.text);
   128    for (const [prop, tag] of MARKS) {
   129      if (node[prop]) {
   130        const wrapper = document.createElement(tag);
   131        wrapper.appendChild(el);
   132        el = wrapper;
   133      }
   134    }
   135    return el;
   136  }
   137  
   138  export class TinaMarkdown extends HTMLElement {
   139    /**
   140     * @type {Object.<string, function(Node): HTMLElement>}
   141     * Register custom components.
   142     *
   143     * @example
   144     * import {TinaMarkdown} from "./node_modules/@tinacms/web-components/dist/tina-markdown.js";
   145     *
   146     * TinaMarkdown.components = {
   147     *     "PostPreview": (node) => {
   148     * 		const el = document.createElement("post-preview");
   149     *
   150     * 		const title = document.createElement("span");
   151     * 		title.slot = "title";
   152     * 		title.textContent = node.props.title ?? "";
   153     * 		el.append(title);
   154     *
   155     * 		return el;
   156     *     },
   157     * };
   158     */
   159    static components = {};
   160  
   161    constructor() {
   162      super();
   163  
   164      this.attachShadow({
   165        mode: 'open',
   166      });
   167    }
   168  
   169    connectedCallback() {
   170      /** @type {string} */
   171      const content = this.getAttribute('content');
   172      /** @type {Node} */
   173      const ast = JSON.parse(content);
   174  
   175      this.shadowRoot.appendChild(renderRichText(ast));
   176    }
   177  }
   178  
   179  customElements.define('tina-markdown', TinaMarkdown);
```
Vuln review text:
```
- File: tina-markdown.js
- Line: 75
- Vulnerability class: Cross-Site Scripting (XSS)
- Quote: `if (node.url && node.type === 'a') el.href = node.url;`

**Explanation:**
The code directly assigns the `url` property from the parsed JSON AST to the `href` attribute of an anchor (`<a>`) element without any sanitization or validation. An attacker can provide a malicious URL such as `javascript:alert(1)`, which will be executed in the context of the user's session when the link is clicked, leading to Stored or Reflected Cross-Site Scripting (XSS).
```
Vuln judge parsed JSON:
```
{
  "cited_ranges": [
    {
      "end": 75,
      "start": 75
    }
  ],
  "rationale": "The review flags line 75, where node.url is assigned to el.href without scheme sanitization, and names javascript: URLs as the XSS vector. That is the same missing guard and weakness as the known vulnerability. It does not mention line 76 (img src), but the href finding matches.",
  "verdict_class_match": true
}
```
Harness verdict: HIT
Fixed review text:
```
I have reviewed the code and found no security vulnerabilities.

The code safely handles the rendering of a JSON AST into HTML:
- **Cross-Site Scripting (XSS):** The code uses `DOMPurify.sanitize` to safely render raw HTML nodes. For other nodes, it uses `document.createElement` and `document.createTextNode`, which inherently protect against XSS by treating content as text rather than executable HTML.
- **URL Sanitization:** Links (`<a>`) and images (`<img>`) have their `href` and `src` attributes sanitized using a dedicated `sanitizeUrl` function, preventing `javascript:` URI-based XSS attacks.
- **Prototype Pollution:** The code accesses `TinaMarkdown.components[node.name]` to resolve custom components. Even if an attacker supplies a malicious `node.name` like `__proto__` or `constructor`, it will only result in a harmless `TypeError` when the code attempts to invoke or append the non-DOM node result, rather than leading to prototype pollution or arbitrary code execution.
- **DOM Manipulation:** The code safely iterates over children and appends them using standard DOM APIs (`appendChild`), which are safe from injection attacks.
```
Fixed judge parsed JSON:
```
{
  "cited_ranges": [],
  "rationale": "The review says the code has no vulnerabilities and that href/src are sanitized with sanitizeUrl. It does not claim the patched URL-scheme vulnerability is still present.",
  "reported_patched_vuln": false
}
```
fixed_clean: true

Human verdict (HIT/PARTIAL/MISS):
Human fixed side (clean/re-reported):
Agree with harness (yes/no):
Notes:

## Sign-off
Run ids: 20261020T145119Z-reviewer-a-3aec9d76, 20261020T160902Z-reviewer-b-e125878d
Judge model: anthropic/claude-sonnet-5-5 (llm)
Judge prompt sha256: 1b281463a5877cde3ffadc1ace4f482c72a6133e1d7bb7d56c345183fd7816b3
Reviewer:
Date:
Signed-off: no
