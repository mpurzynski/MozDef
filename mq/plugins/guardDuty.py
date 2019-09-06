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

        with open(
            os.path.join(os.path.dirname(__file__), "guardduty_mapping.yml"), "r"
        ) as f:
            mapping_map = f.read()

        yap = yaml.safe_load(mapping_map)
        self.eventtypes = list(yap.keys())
        self.yap = yap
        del (mapping_map)

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
                current_pointer[updated_key] = toUTC(
                    current_pointer[updated_key]
                ).isoformat()
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

        print(message)

        for ipaddress_key in self.ipaddress_keys:
            if "sourceipaddress" not in message["details"]:
                if key_exists(ipaddress_key, message):
                    message.details.sourceipaddress = message.get(ipaddress_key)

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

        # reformat the date fields to isoformat
        for date_key in self.date_keys:
            if key_exists(date_key, message):
                if message.get(date_key) is None:
                    continue
                else:
                    message = self.convert_key_date_format(date_key, message)
        newmessage = dict()
        newmessage["receivedtimestamp"] = message["receivedtimestamp"]
        newmessage["timestamp"] = message["timestamp"]
        newmessage["utctimestamp"] = message["utctimestamp"]
        newmessage["processname"] = message["processname"]
        newmessage["processid"] = message["processid"]
        newmessage["severity"] = message["severity"]
        newmessage["mozdefhostname"] = message["mozdefhostname"]
        newmessage["tags"] = ["aws", "guardduty"] + message["tags"]
        newmessage["category"] = "guardduty"
        newmessage["source"] = "guardduty"
        newmessage["customendpoint"] = ""
        newmessage["details"] = {}
        newmessage["details"]["type"] = message["details"]["finding"]["action"][
            "actiontype"
        ].lower()
        # import code
        # code.interact(local=locals())
        newmessage["details"]["finding"] = message["category"]
        newmessage["summary"] = message["details"]["title"]
        newmessage["details"]["resourcerole"] = message["details"]["finding"][
            "resourcerole"
        ].lower()

        if message["category"] in self.eventtypes:
            for key in self.yap[newmessage["details"]["finding"]]:
                mappedvalue = jmespath.search(
                    self.yap[newmessage["details"]["finding"]][key], message
                )
                # JMESPath likes to silently return a None object
                if mappedvalue is not None:
                    newmessage[key] = mappedvalue

        return (newmessage, metadata)


# XXX: Remove the stub later
j2 = {
    "receivedtimestamp": "2019-08-21T21:01:11.288139+00:00",
    "mozdefhostname": "mozdefqa2.private.mdc1.mozilla.com",
    "tags": ["gd2md-GuardDutyEventNormalization-5HTB8BEL5Y1Q-SqsOutput-1D5MQWALTYJ8P"],
    "severity": "INFO",
    "details": {
        "severity": 2,
        "tags": ["PORT_PROBE"],
        "schemaversion": "2.0",
        "accountid": "692406183521",
        "region": "us-west-2",
        "partition": "aws",
        "id": "96b65ab53d3c18c0b145814c2f8c7673",
        "arn": "arn:aws:guardduty:us-west-2:692406183521:detector/90b4e5d7bef5a2adc076a62bd3d88c78/finding/96b65ab53d3c18c0b145814c2f8c7673",
        "type": "Recon:EC2/PortProbeUnprotectedPort",
        "resource": {
            "resourcetype": "Instance",
            "instancedetails": {
                "instanceid": "i-00c19ca3bf7d2e7db",
                "instancetype": "c3.xlarge",
                "launchtime": "2019-08-21T17:42:09Z",
                "platform": None,
                "productcodes": [],
                "iaminstanceprofile": None,
                "networkinterfaces": [
                    {
                        "ipv6addresses": [],
                        "networkinterfaceid": "eni-0133432eb01499238",
                        "privatednsname": "ip-10-144-29-94.us-west-2.compute.internal",
                        "privateipaddress": "10.144.29.94",
                        "privateipaddresses": [
                            {
                                "privatednsname": "ip-10-144-29-94.us-west-2.compute.internal",
                                "privateipaddress": "10.144.29.94",
                            }
                        ],
                        "subnetid": "subnet-d948b6bf",
                        "vpcid": "vpc-35df7053",
                        "securitygroups": [
                            {
                                "groupname": "docker-worker - gecko-workers",
                                "groupid": "sg-2728435d",
                            }
                        ],
                        "publicdnsname": "ec2-54-218-76-206.us-west-2.compute.amazonaws.com",
                        "publicip": "54.218.76.206",
                    }
                ],
                "tags": [
                    {"key": "Name", "value": "gecko-t-linux-xlarge"},
                    {
                        "key": "WorkerType",
                        "value": "ec2-manager-production/gecko-t-linux-xlarge",
                    },
                    {"key": "Owner", "value": "ec2-manager-production"},
                ],
                "instancestate": "running",
                "availabilityzone": "us-west-2a",
                "imageid": "ami-0f4a83b0dd042b564",
                "imagedescription": "null",
            },
        },
        "createdat": "2019-08-21T18:22:30.008Z",
        "updatedat": "2019-08-21T20:44:48.673Z",
        "title": "Unprotected port on EC2 instance i-00c19ca3bf7d2e7db is being probed.",
        "description": "EC2 instance has an unprotected port which is being probed by a known malicious host.",
        "finding": {
            "servicename": "guardduty",
            "detectorid": "90b4e5d7bef5a2adc076a62bd3d88c78",
            "action": {
                "actiontype": "PORT_PROBE",
                "portprobeaction": {
                    "portprobedetails": [
                        {
                            "localportdetails": {"port": 33895, "portname": "Unknown"},
                            "remoteipdetails": {
                                "ipaddressv4": "81.22.45.239",
                                "organization": {
                                    "asn": "49505",
                                    "asnorg": "OOO Network of data-centers Selectel",
                                    "isp": "Infolink LLC",
                                    "org": "Infolink LLC",
                                },
                                "country": {"countryname": "Russia"},
                                "city": {"cityname": ""},
                                "geolocation": {"lat": 55.7386, "lon": 37.6068},
                            },
                        },
                        {
                            "localportdetails": {"port": 33201, "portname": "Unknown"},
                            "remoteipdetails": {
                                "ipaddressv4": "185.176.27.42",
                                "organization": {
                                    "asn": "204428",
                                    "asnorg": "SS-Net",
                                    "isp": "IP Khnykin Vitaliy Yakovlevich",
                                    "org": "IP Khnykin Vitaliy Yakovlevich",
                                },
                                "country": {"countryname": "Russia"},
                                "city": {"cityname": ""},
                                "geolocation": {"lat": 55.7386, "lon": 37.6068},
                            },
                        },
                        {
                            "localportdetails": {"port": 33089, "portname": "Unknown"},
                            "remoteipdetails": {
                                "ipaddressv4": "92.63.194.74",
                                "organization": {
                                    "asn": "48817",
                                    "asnorg": "Chelyshev Sergej Aleksandrovich",
                                    "isp": "OOO Patent-Media",
                                    "org": "OOO Patent-Media",
                                },
                                "country": {"countryname": "Ukraine"},
                                "city": {"cityname": ""},
                                "geolocation": {"lat": 50.45, "lon": 30.5233},
                            },
                        },
                    ],
                    "blocked": False,
                },
            },
            "resourcerole": "TARGET",
            "additionalinfo": {"threatname": "Scanner", "threatlistname": "ProofPoint"},
            "evidence": {
                "threatintelligencedetails": [
                    {"threatnames": ["Scanner"], "threatlistname": "ProofPoint"}
                ]
            },
            "eventfirstseen": "2019-08-21T18:06:13Z",
            "eventlastseen": "2019-08-21T20:34:12Z",
            "archived": False,
            "count": 3,
        },
    },
    "timestamp": "2019-08-21T21:01:09.004000+00:00",
    "utctimestamp": "2019-08-21T21:01:09.004000+00:00",
    "hostname": "i-00c19ca3bf7d2e7db",
    "processname": "guardduty",
    "processid": "1337",
    "summary": "EC2 instance has an unprotected port which is being probed by a known malicious host.",
    "category": "Recon:EC2/PortProbeUnprotectedPort",
    "type": "event",
    "source": "guardduty",
}

mq_plugin = message()
# r = mq_plugin.onMessage(sample_guardduty_dict, {})
r = mq_plugin.onMessage(j2, {})
print(r)
