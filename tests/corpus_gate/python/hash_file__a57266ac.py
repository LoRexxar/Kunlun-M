import hashlib

from core.analytics import InlineAnalytics
from core.observables import Hash

HASH_TYPES_DICT = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


class HashFile(InlineAnalytics):
    default_values = {
        "name": "HashFile",
        "description": "Extracts MD5, SHA1, SHA256, SHA512 hashes from file",
    }

    ACTS_ON = ["File", "Certificate"]

    @staticmethod
    def each(f):
        if f.body:
            f.hashes = []
            for hash_type, h in HashFile.extract_hashes(f.body.contents):
                hash_object = Hash.get_or_create(value=h.hexdigest())
                hash_object.add_source("analytics")
                hash_object.save()
                f.active_link_to(
                    hash_object,
                    "{} hash".format(hash_type.upper()),
                    "HashFile",
                    clean_old=False,
                )
                f.hashes.append({"hash": hash_type, "value": h.hexdigest()})
            f.save()

    @staticmethod
    def extract_hashes(body_contents):
        hashers = {k: HASH_TYPES_DICT[k]() for k in HASH_TYPES_DICT}

        while True:
            chunk = body_contents.read(512 * 16)
            if not chunk:
                break
            for h in hashers.values():
                h.update(chunk)

        return hashers.items()
