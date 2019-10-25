# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2017 Mozilla Corporation

from mozdef_util.utilities.key_exists import key_exists
from mozdef_util.utilities.toUTC import toUTC
from mozdef_util.utilities.dot_dict import DotDict
import os
import yaml
import jmespath


class message(object):
    def __init__(self):
        """
            Plugin used to fix object type discretions with cloudtrail messages
        """
        self.registration = ["guardduty"]
        self.priority = 5

        try:
            self.mozdefhostname = "{0}".format(node())
        except:
            self.mozdefhostname = "failed to fetch mozdefhostname"
            pass

        with open(os.path.join(os.path.dirname(__file__), "guardduty_mapping.yml"), "r") as f:
            mapping_map = f.read()

        yap = yaml.safe_load(mapping_map)
        self.eventtypes = list(yap.keys())
        self.yap = yap
        del mapping_map

        # AWS guard duty sends dates as iso_8601 which ES doesn't appreciate
        # here's a list of date fields we'll convert to isoformat
        self.date_keys = [
            "details.finding.eventlastseen",
            "details.finding.eventfirstseen",
            "details.resource.instancedetails.launchtime",
            "details.createdat",
            "details.updatedat",
        ]

        # AWS guard duty can send IPs in a bunch of places
        # Lets pick out some likely targets and format them
        # so other mozdef plugins can rely on their location
        self.ipaddress_keys = [
            "details.finding.action.networkconnectionaction.remoteipdetails.ipaddressv4",
            "details.finding.action.awsapicallaction.remoteipdetails.ipadrressv4",
        ]

    def convert_key_date_format(self, needle, haystack):
        num_levels = needle.split(".")
        if len(num_levels) == 0:
            return False
        current_pointer = haystack
        for updated_key in num_levels:
            if updated_key == num_levels[-1]:
                current_pointer[updated_key] = toUTC(current_pointer[updated_key]).isoformat()
                return haystack
            if updated_key in current_pointer:
                current_pointer = current_pointer[updated_key]
            else:
                return haystack

    def onMessage(self, message, metadata):
        if "source" not in message:
            return (message, metadata)

        if not message["source"] == "guardduty":
            return (message, metadata)

        if "details" not in message:
            return (message, metadata)

        # for ipaddress_key in self.ipaddress_keys:
        #    if "sourceipaddress" not in message["details"]:
        #        if key_exists(ipaddress_key, message):
        #            message.details.sourceipaddress = message.get(ipaddress_key)

        # if we still haven't found what we are looking for #U2
        # sometimes it's in a list
        # if "sourceipaddress" not in message["details"]:
        #    if key_exists(
        #        "details.finding.action.portprobeaction.portprobedetails", message
        #    ) and isinstance(
        #        message.details.finding.action.portprobeaction.portprobedetails, list
        #    ):
        #
        #        # inspect the first list entry and see if it contains an IP
        #        # we will have a data loss here because GD data have a random structure
        #        # to avoid data loss here every GD message would need to be broken into several messages
        #        portprobedetails = DotDict(
        #            message.details.finding.action.portprobeaction.portprobedetails[0]
        #        )
        #        if key_exists("remoteipdetails.ipaddressv4", portprobedetails):
        #            message.details.sourceipaddress = (
        #                portprobedetails.remoteipdetails.ipaddressv4
        #            )

        # XXX: use it later to re-format & rewrite additional fields
        # reformat the date fields to isoformat
        # for date_key in self.date_keys:
        #    if key_exists(date_key, message):
        #        if message.get(date_key) is None:
        #            continue
        #        else:
        #            message = self.convert_key_date_format(date_key, message)
        newmessage = dict()
        newmessage["receivedtimestamp"] = message["receivedtimestamp"]
        newmessage["timestamp"] = message["timestamp"]
        newmessage["utctimestamp"] = message["utctimestamp"]
        newmessage["processname"] = "FIXME"
        newmessage["processid"] = "FIXME"
        newmessage["severity"] = "FIXME"
        newmessage["mozdefhostname"] = message["mozdefhostname"]
        newmessage["tags"] = ["aws", "guardduty"] + message["tags"]
        newmessage["category"] = "guardduty"
        newmessage["source"] = "guardduty"
        newmessage["customendpoint"] = ""
        newmessage["details"] = {}
        newmessage["details"]["type"] = message["details"]["finding"]["action"]["actionType"].lower()
        newmessage["details"]["finding"] = message['details']["category"]
        newmessage["summary"] = message["details"]["title"]
        newmessage["details"]["resourcerole"] = message["details"]["finding"]["resourceRole"].lower()

        if message["details"]["category"] in self.eventtypes:
            for key in self.yap[newmessage["details"]["finding"]]:
                mappedvalue = jmespath.search(self.yap[newmessage["details"]["finding"]][key], message)
                # JMESPath likes to silently return a None object
                if mappedvalue is not None:
                    newmessage["details"][key] = mappedvalue

        return (newmessage, metadata)
