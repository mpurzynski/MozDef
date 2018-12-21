#!/usr/bin/env python
import requests
import logging
from sys import argv, exit
from os import fsync, stat, rename
from configlib import getConfig, OptionParser
from logging.handlers import SysLogHandler
from mozdef_util.utilities.logger import logger, initLogger


def main():
    parser = OptionParser()
    parser.add_option(
        "-c",
        dest="configfile",
        default=argv[0].replace(".py", ".conf"),
        help="configuration file to use",
    )
    (options, args) = parser.parse_args()

    output = getConfig("output", "stdout", options.configfile)
    options.url = getConfig(
        "url", "http://standards-oui.ieee.org/oui.txt", options.configfile
    )
    options.tmpfile = getConfig("tmpfile", "/tmp/oui.txt.tmp", options.configfile)
    options.dstfile = getConfig("dstfile", "/tmp/oui.txt", options.configfile)
    options.minsize = getConfig("minsize", 4000000, options.configfile)

    initLogger(options)
    logger.level = logging.DEBUG

    try:
        r = requests.get(url=options.url, timeout=10)
    except (
        requests.exceptions.HTTPError,
        requests.exceptions.ConnectionError,
        requests.exceptions.ProxyError,
        requests.exceptions.TooManyRedirects,
        requests.exceptions.Timeout,
    ) as e:
        logger.error("Failed to download the OUI database {0}".format(e))
        exit(1)

    try:
        r.raise_for_status()
    except requests.exceptions.HTTPError as e:
        logger.exception("Error received from the server {0}".format(e))
        exit(2)

    with open(options.tmpfile, "wb") as fout:
        try:
            fout.write(r.text.encode("utf8"))
        except IOError as e:
            logger.exception("Error when writing to the temporary file {0}".format(e))
            exit(3)
        # Flush glibc buffers and write dirty pages
        # Does not cause a global pagecache writeback
        fout.flush()
        fsync(fout.fileno())

    size = stat(options.tmpfile).st_size
    if size > options.minsize:
        # This is atomic on POSIX
        try:
            rename(options.tmpfile, options.dstfile)
        except OSError as e:
            logger.exception(
                "Failed to move the temporary file to the destination file {0}".format(
                    e
                )
            )
            exit(4)


if __name__ == "__main__":
    main()
