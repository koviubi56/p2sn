from setuptools import setup

P2SN = True
try:
    import p2sn
except Exception:
    try:
        from . import p2sn
    except Exception:
        try:
            from .src import p2sn
        except Exception:
            from warnings import warn

            warn(
                "Could not import p2sn; setting up without informations about"
                " the project.",
                UserWarning,
            )
            P2SN = False

if __name__ == "__main__":
    kwargs = {"name": "p2sn", "package_dir": {"": "src"}}
    if P2SN:
        try:
            classifiers = []
            _in = False
            with open("setup.cfg", "r", encoding="utf-8") as f:
                for line in f:
                    if (
                        line.strip()
                        == "# -----START OF CLASSIFIERS-----"
                    ):
                        _in = True
                    elif (
                        line.strip()
                        == "# -----END OF CLASSIFIERS-----"
                    ):
                        _in = False
                    elif _in:
                        classifiers.append(line.strip())
        except Exception:
            classifiers = []
        setup(
            version=p2sn.__version__,
            description=p2sn.__description__,
            long_description="README.md",
            author=p2sn.__author__,
            author_email=p2sn.__email__,
            maintainer=p2sn.__author__,
            maintainer_email=p2sn.__email__,
            url=p2sn.__url__,
            download_url=p2sn.__url__,
            classifiers=classifiers,
            license=p2sn.__license__,
            keywords=[
                "Metadata-Version: 1.1",
                "Name: p2sn",
                f"Version: {p2sn.__version__}",
                f"Summary: {p2sn.__description__}"
                f"Description: {p2sn.__description__}",
                f"Home-page: {p2sn.__url__}",
                f"Author: {p2sn.__author__}",
                f"Author-email: {p2sn.__email__}",
                f"License: {p2sn.__license__}",
                f"Classifier: {', '.join(classifiers)}"
                if classifiers
                else "",
                "Requires: rsa >= 4.8",
            ],
            **kwargs,
        )

    else:
        setup(**kwargs)
