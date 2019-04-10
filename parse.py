import pandas as pd
import binascii
import io
import json
import math
import os
import glob
import tempfile
from datetime import datetime
from struct import unpack

from schema import PidTagSchema, PidTypeSchema
from pathlib import Path


# this is the table of tags and codes

def hexify(PropID):
    return "{0:#0{1}x}".format(PropID, 10).upper()[2:]


def lookup(ulPropID):
    if hexify(ulPropID) in PidTagSchema:
        (PropertyName, PropertyType) = PidTagSchema[hexify(ulPropID)]
        return PropertyName
    else:
        return hex(ulPropID)


class GalParser(object):

    GAL_PATH = r"AppData\Local\Microsoft\Outlook\Offline Address Books\**\udetails.oab"

    def __init__(self, output_path, gal_path=None):
        self.output_path = output_path if output_path is not None else os.path.join(str(Path.home()), "output.csv")
        self.gal_path = gal_path if gal_path is not None else self.get_gal_path()
        self.temp_file_ = None
        self.unknown_indices = set([])
        self.unknown_indices_names = {}

    @property
    def temp_file(self):
        if self.temp_file_ and os.path.exists(self.temp_file_):
            return self.temp_file_
        else:
            self.temp_file_ = tempfile.NamedTemporaryFile("w+b")
            return self.temp_file_

    def warn_unknown_index(self, prop_id):
        if prop_id not in self.unknown_indices:
            self.unknown_indices.add(prop_id)
            print("Unknown index {}".format(prop_id))

    def get_gal_path(self):
        home_path = str(Path.home())
        glob_path = os.path.join(home_path, self.GAL_PATH)
        gal_path = glob.glob(glob_path, recursive=True)
        if not gal_path:
            raise FileNotFoundError
        else:
            return gal_path[0]

    def parse(self):

        json_out = self.temp_file
        with open(self.gal_path, 'rb') as f:
            (ulVersion, ulSerial, ulTotRecs) = unpack('<III', f.read(4 * 3))
            assert ulVersion == 32, 'This only supports OAB Version 4 Details File'

            # OAB_META_DATA
            cbSize = unpack('<I', f.read(4))[0]

            meta = io.BytesIO(f.read(cbSize - 4))
            # the length of the header attributes
            # we don't know and don't really need to know how to parse these
            HDR_cAtts = unpack('<I', meta.read(4))[0]

            for rgProp in range(HDR_cAtts):
                ulPropID = unpack('<I', meta.read(4))[0]
                ulFlags = unpack('<I', meta.read(4))[0]

            # these are the attributes that we actually care about
            OAB_cAtts = unpack('<I', meta.read(4))[0]
            OAB_Atts = []

            for rgProp in range(OAB_cAtts):
                ulPropID = unpack('<I', meta.read(4))[0]
                ulFlags = unpack('<I', meta.read(4))[0]

                OAB_Atts.append(ulPropID)

            # OAB_V4_REC (Header Properties)
            cbSize = unpack('<I', f.read(4))[0]
            f.read(cbSize - 4)

            # now for the actual stuff
            while True:
                read = f.read(4)
                if read == b'':
                    break
                # this is the size of the chunk, incidentally its inclusive
                cbSize = unpack('<I', read)[0]
                # so to read the rest, we subtract four
                chunk = io.BytesIO(f.read(cbSize - 4))
                # wow such bit op
                presenceBitArray = bytearray(chunk.read(int(math.ceil(OAB_cAtts / 8.0))))
                indices = [i for i in range(OAB_cAtts) if (presenceBitArray[i // 8] >> (7 - (i % 8))) & 1 == 1]

                def read_str():
                    # strings in the OAB format are null-terminated
                    buf = b""
                    while True:
                        n = chunk.read(1)
                        if n == b"\0" or n == b"":
                            break
                        buf += n
                    return buf.decode('utf-8')

                # return unicode(buf, errors="ignore")

                def read_int():
                    # integers are cool aren't they
                    byte_count = unpack('<B', chunk.read(1))[0]
                    if 0x81 <= byte_count <= 0x84:
                        byte_count = unpack('<I', (chunk.read(byte_count - 0x80) + b"\0\0\0")[0:4])[0]
                    else:
                        assert byte_count <= 127, "byte count must be <= 127"
                    return byte_count

                def stringify_bytes(record_data):
                    output_data = {}
                    for k, v in record_data.items():
                        if isinstance(v, str):
                            output_data[k] = v
                        elif isinstance(v, bytes):
                            output_data[k] = v.decode()
                        elif isinstance(v, list):
                            temp_list = []
                            for val in v:
                                if isinstance(val, bytes):
                                    try:
                                        decoded = val.decode('utf-8')
                                    except:
                                        decoded = ""
                                    temp_list.append(decoded)
                                else:
                                    temp_list.append(val)

                            output_data[k] = temp_list
                    return output_data

                rec = {}

                for i in indices:
                    PropID = hexify(OAB_Atts[i])
                    if PropID not in PidTagSchema:
                        self.warn_unknown_index(PropID)
                        Name, Type = PropID, PidTypeSchema[PropID[-4:]]
                    else:
                        Name, Type = PidTagSchema[PropID]

                    if Type == "PtypString8" or Type == "PtypString":
                        val = read_str()
                        rec[Name] = val

                    elif Type == "PtypBoolean":
                        val = unpack('<?', chunk.read(1))[0]
                        rec[Name] = val

                    elif Type == "PtypInteger32":
                        val = read_int()
                        rec[Name] = val

                    elif Type == "PtypBinary":
                        bin = chunk.read(read_int())
                        rec[Name] = binascii.b2a_hex(bin)

                    elif Type == "PtypMultipleString" or Type == "PtypMultipleString8":
                        byte_count = read_int()

                        arr = []
                        for i in range(byte_count):
                            val = read_str()
                            arr.append(val)

                        rec[Name] = arr

                    elif Type == "PtypMultipleInteger32":
                        byte_count = read_int()

                        arr = []
                        for i in range(byte_count):
                            val = read_int()
                            if Name == "OfflineAddressBookTruncatedProperties":
                                val = hexify(val)
                                if val in PidTagSchema:
                                    val = PidTagSchema[val][0]
                            arr.append(val)

                        rec[Name] = arr

                    elif Type == "PtypMultipleBinary":
                        byte_count = read_int()

                        arr = []
                        for i in range(byte_count):
                            bin_len = read_int()
                            bin = chunk.read(bin_len)
                            arr.append(binascii.b2a_hex(bin))

                        rec[Name] = arr
                    else:
                        raise "Unknown property type (" + Type + ")"

                remains = chunk.read()
                if len(remains) > 0:
                    raise "This record contains unexpected data at the end: " + remains

                rec = stringify_bytes(rec)

                json_out.write(json.dumps(rec).encode() + b'\n')

        # get the JSON format into something pandas can parse
        json_out.seek(0)
        raw_data = json_out.read()
        encoded_data = raw_data.decode()
        del raw_data
        encoded_lines = encoded_data.splitlines()
        del encoded_data
        json_data = [json.loads(x) for x in encoded_lines]
        del encoded_lines

        df = pd.DataFrame(json_data)
        del json_data
        df.to_csv(self.output_path, index=False)


if __name__ == "__main__":
    output_path = input("Where should the JSON file be saved? Enter an empty string to save CSV file to user folder")
    if output_path == "":
        output_path = None
    gal_path = input("Enter the path to GAL or a blank string to search for GAL")
    if gal_path == "":
        gal_path = None
    gal_parse = GalParser(output_path=output_path, gal_path=gal_path)
    start_time = datetime.now()
    # parse the oab file to newline separated json
    print("Starting .oab parse")
    gal_parse.parse()
    elapsed = datetime.now() - start_time
    print("Finished .oab parse in {}".format(elapsed))
