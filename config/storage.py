from whitenoise.storage import CompressedManifestStaticFilesStorage


class StaticFilesStorage(CompressedManifestStaticFilesStorage):
    """Keep hashed production assets while allowing isolated test renders."""

    manifest_strict = False
