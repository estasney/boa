import argparse
import binascii
import io
import json
import math
import os
from datetime import datetime
from struct import unpack

from schema import PidTagSchema


# this is the table of tags and codes

def hexify(PropID):
    return "{0:#0{1}x}".format(PropID, 10).upper()[2:]


def lookup(ulPropID):
    if hexify(ulPropID) in PidTagSchema:
        (PropertyName, PropertyType) = PidTagSchema[hexify(ulPropID)]
        return PropertyName
    else:
        return hex(ulPropID)


parser = argparse.ArgumentParser()
parser.add_argument('-o', '--output', help="Destination json file")
parser.add_argument('oabfile', metavar='OABFILE', type=str, nargs=1,
                    help=r'Path to OAB File. Typically found in '
                         r'C:\Users\%username%\AppData\Local\Microsoft\Outlook\Offline Address Books\..\udetails.cab')


def parse_oab(oab_path, output_path):

    counter = 0
    json_out = open(output_path, 'w')

    with open(oab_path, 'rb') as f:
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
                    raise "This property id (" + PropID + ") does not exist in the schema"

                (Name, Type) = PidTagSchema[PropID]

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

            json_out.write(json.dumps(rec) + '\n')


if __name__ == "__main__":
    start_time = datetime.now()
    args = parser.parse_args()
    if args.output is None:
        raise Exception("Output path is required")
    else:
        json_out = args.output

    # parse the oab file to newline separated json
    print("Starting .oab parse")
    parse_oab(args.oabfile[0], json_out)
    elapsed = datetime.now() - start_time
    print("Finished .oab parse in {}".format(elapsed))


    # read the output file into memory and write it back out as valid JSON

    def get_original_json():
        with open(args.output, 'r') as data_file:
            return [json.loads(x) for x in data_file.read().splitlines()]


    print("Validating JSON Data")
    start = datetime.now()
    data = get_original_json()
    os.remove(args.output)
    elapsed = datetime.now() - start
    print("Finished Validating JSON in {}".format(elapsed))

    print("Dumping JSON")
    with open(args.output, 'w+') as json_file:
        json.dump(data, json_file)
    print("Finished JSON")
    elapsed = datetime.now() - start_time
    print("Finished process in {}".format(elapsed))
