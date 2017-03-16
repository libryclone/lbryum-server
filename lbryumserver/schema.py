import json

from lbryschema.schema import VERSION_NAMES
from lbryschema.legacy.migrate import migrate as schema_migrator
from lbryschema.claim import ClaimDict

from lbryumserver.utils import print_log, print_warning
from google.protobuf import json_format
from google.protobuf.internal.decoder import _DecodeError


def migrate_json_claim_value(name, claim_value):
    try:
        decoded_json = json.loads(claim_value)
        pb_migrated = schema_migrator(decoded_json)
        print_log("Migrated lbry://%s from json to protobuf schema version %s" % (name,
                                                VERSION_NAMES[pb_migrated.protobuf.version]))
        return pb_migrated
    except json_format.ParseError as parse_error:
        print_warning("Failed to migrate lbry://%s to protobuf: %s" % (name, parse_error))
    except Exception as err:
        print_warning("Failed to migrate lbry://%s to protobuf: %s" % (name, err))


def decode_claim_value(name, claim_value):
    try:
        decoded_pb = ClaimDict.deserialize(claim_value)
        print_warning("Decoded protobuf for lbry://%s" % name)
    except _DecodeError:
        migrate_json_claim_value(name, claim_value)
