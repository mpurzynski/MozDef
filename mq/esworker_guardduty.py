#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2017 Mozilla Corporation


import json

import sys
import os
import socket
import time
from configlib import getConfig, OptionParser
from datetime import datetime
import pytz

from mozdef_util.utilities.toUTC import toUTC
from mozdef_util.utilities.logger import logger, initLogger
from mozdef_util.elasticsearch_client import (
    ElasticsearchClient,
    ElasticsearchBadServer,
    ElasticsearchInvalidIndex,
    ElasticsearchException,
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../"))
from mq.lib.plugins import sendEventToPlugins, registerPlugins
from mq.lib.sqs import connect_sqs
from esworker_sns_sqs import taskConsumer


# running under uwsgi?
try:
    import uwsgi

    hasUWSGI = True
except ImportError as e:
    hasUWSGI = False


class GDtaskConsumer(taskConsumer):
    def on_message(self, message_raw):
        # default elastic search metadata for an event
        metadata = {"index": "events", "id": None}
        event = {}

        event["receivedtimestamp"] = toUTC(datetime.now()).isoformat()
        event["mozdefhostname"] = self.options.mozdefhostname

        if "tags" in event:
            event["tags"].extend([self.options.taskexchange])
        else:
            event["tags"] = [self.options.taskexchange]

        event["severity"] = "INFO"
        event["source"] = "guardduty"
        event["details"] = {}

        if "Message" in message_raw:
            message = {}
            message = json.loads(message_raw["Message"])
            if "details" in message:
                if "finding" in message["details"]:
                    if "action" in message["details"]["finding"]:
                        if "actionType" in message["details"]["finding"]["action"]:
                            if message["details"]["finding"]["action"]["actionType"] == "PORT_PROBE":
                                if "portProbeAction" in message["details"]["finding"]["action"]:
                                    if "portProbeDetails" in message["details"]["finding"]["action"]["portProbeAction"]:
                                        for probe in message["details"]["finding"]["action"]["portProbeAction"][
                                            "portProbeDetails"
                                        ]:
                                            print("victim {0}".format(probe["localPortDetails"]))
                                            print("actor {0}".format(probe["remoteIpDetails"]))
            event["details"] = message["details"]
            if "hostname" in message:
                event["hostname"] = message["hostname"]
            if "summary" in message:
                event["summary"] = message["summary"]
            if "category" in message:
                event["details"]["category"] = message["category"]
            if "tags" in message:
                event["details"]["tags"] = message["tags"]
            event["utctimestamp"] = toUTC(message["timestamp"]).isoformat()
            event["timestamp"] = event["utctimestamp"]
            (event, metadata) = sendEventToPlugins(event, metadata, self.pluginList)
            # Drop message if plugins set to None
            if event is None:
                return
            # self.save_event(event, metadata)
            print("I would save event now")


def esConnect():
    """open or re-open a connection to elastic search"""
    return ElasticsearchClient((list("{0}".format(s) for s in options.esservers)), options.esbulksize)


def initConfig():
    # capture the hostname
    options.mozdefhostname = getConfig("mozdefhostname", socket.gethostname(), options.configfile)

    # elastic search options. set esbulksize to a non-zero value to enable bulk posting, set timeout to post no matter how many events after X seconds.
    options.esservers = list(getConfig("esservers", "http://localhost:9200", options.configfile).split(","))
    options.esbulksize = getConfig("esbulksize", 0, options.configfile)
    options.esbulktimeout = getConfig("esbulktimeout", 30, options.configfile)

    # set to sqs for Amazon
    options.mqprotocol = getConfig("mqprotocol", "sqs", options.configfile)

    # rabbit message queue options
    options.taskexchange = getConfig("taskexchange", "eventtask", options.configfile)
    # rabbit: how many messages to ask for at once from the message queue
    options.prefetch = getConfig("prefetch", 10, options.configfile)

    # aws options
    options.accesskey = getConfig("accesskey", "", options.configfile)
    options.secretkey = getConfig("secretkey", "", options.configfile)
    options.region = getConfig("region", "", options.configfile)

    # How long to sleep between polling
    options.sleep_time = getConfig("sleep_time", 0.1, options.configfile)


def main():
    if hasUWSGI:
        logger.info("started as uwsgi mule {0}".format(uwsgi.mule_id()))
    else:
        logger.info("started without uwsgi")

    if options.mqprotocol not in ("sqs"):
        logger.error("Can only process SQS queues, terminating")
        sys.exit(1)

    sqs_queue = connect_sqs(
        region_name=options.region,
        aws_access_key_id=options.accesskey,
        aws_secret_access_key=options.secretkey,
        task_exchange=options.taskexchange,
    )
    # consume our queue
    GDtaskConsumer(sqs_queue, es, options).run()


if __name__ == "__main__":
    # configure ourselves
    parser = OptionParser()
    parser.add_option(
        "-c", dest="configfile", default=sys.argv[0].replace(".py", ".conf"), help="configuration file to use"
    )
    (options, args) = parser.parse_args()
    initConfig()
    initLogger(options)

    # open ES connection globally so we don't waste time opening it per message
    es = esConnect()

    try:
        main()
    except KeyboardInterrupt as e:
        logger.info("Exiting worker")
        if options.esbulksize != 0:
            es.finish_bulk()
    except Exception as e:
        if options.esbulksize != 0:
            es.finish_bulk()
        raise

# y = {
#    'receivedtimestamp': '2019-08-21T21:01:11.288139+00:00',
#    'mozdefhostname': 'mozdefqa2.private.mdc1.mozilla.com',
#    'tags': ['gd2md-GuardDutyEventNormalization-5HTB8BEL5Y1Q-SqsOutput-1D5MQWALTYJ8P'],
#    'severity': 'INFO',
#    'details': {
#        'severity': 2,
#        'tags': ['PORT_PROBE'],
#        'schemaversion': '2.0',
#        'accountid': '692406183521',
#        'region': 'us-west-2',
#        'partition': 'aws',
#        'id': '96b65ab53d3c18c0b145814c2f8c7673',
#        'arn': 'arn:aws:guardduty:us-west-2:692406183521:detector/90b4e5d7bef5a2adc076a62bd3d88c78/finding/96b65ab53d3c18c0b145814c2f8c7673',
#        'type': 'Recon:EC2/PortProbeUnprotectedPort',
#        'resource': {
#            'resourcetype': 'Instance',
#            'instancedetails': {
#                'instanceid': 'i-00c19ca3bf7d2e7db',
#                'instancetype': 'c3.xlarge',
#                'launchtime': '2019-08-21T17:42:09Z',
#                'platform': None,
#                'productcodes': [],
#                'iaminstanceprofile': None,
#                'networkinterfaces': [
#                    {
#                        'ipv6addresses': [],
#                        'networkinterfaceid': 'eni-0133432eb01499238',
#                        'privatednsname': 'ip-10-144-29-94.us-west-2.compute.internal',
#                        'privateipaddress': '10.144.29.94',
#                        'privateipaddresses': [
#                            {
#                                'privatednsname': 'ip-10-144-29-94.us-west-2.compute.internal',
#                                'privateipaddress': '10.144.29.94',
#                            }
#                        ],
#                        'subnetid': 'subnet-d948b6bf',
#                        'vpcid': 'vpc-35df7053',
#                        'securitygroups': [{'groupname': 'docker-worker - gecko-workers', 'groupid': 'sg-2728435d'}],
#                        'publicdnsname': 'ec2-54-218-76-206.us-west-2.compute.amazonaws.com',
#                        'publicip': '54.218.76.206',
#                    }
#                ],
#                'tags': [
#                    {'key': 'Name', 'value': 'gecko-t-linux-xlarge'},
#                    {'key': 'WorkerType', 'value': 'ec2-manager-production/gecko-t-linux-xlarge'},
#                    {'key': 'Owner', 'value': 'ec2-manager-production'},
#                ],
#                'instancestate': 'running',
#                'availabilityzone': 'us-west-2a',
#                'imageid': 'ami-0f4a83b0dd042b564',
#                'imagedescription': 'null',
#            },
#        },
#        'createdat': '2019-08-21T18:22:30.008Z',
#        'updatedat': '2019-08-21T20:44:48.673Z',
#        'title': 'Unprotected port on EC2 instance i-00c19ca3bf7d2e7db is being probed.',
#        'description': 'EC2 instance has an unprotected port which is being probed by a known malicious host.',
#        'finding': {
#            'servicename': 'guardduty',
#            'detectorid': '90b4e5d7bef5a2adc076a62bd3d88c78',
#            'action': {
#                'actiontype': 'PORT_PROBE',
#                'portprobeaction': {
#                    'portprobedetails': [
#                        {
#                            'localportdetails': {'port': 33895, 'portname': 'Unknown'},
#                            'remoteipdetails': {
#                                'ipaddressv4': '81.22.45.239',
#                                'organization': {
#                                    'asn': '49505',
#                                    'asnorg': 'OOO Network of data-centers Selectel',
#                                    'isp': 'Infolink LLC',
#                                    'org': 'Infolink LLC',
#                                },
#                                'country': {'countryname': 'Russia'},
#                                'city': {'cityname': ''},
#                                'geolocation': {'lat': 55.7386, 'lon': 37.6068},
#                            },
#                        },
#                        {
#                            'localportdetails': {'port': 33201, 'portname': 'Unknown'},
#                            'remoteipdetails': {
#                                'ipaddressv4': '185.176.27.42',
#                                'organization': {
#                                    'asn': '204428',
#                                    'asnorg': 'SS-Net',
#                                    'isp': 'IP Khnykin Vitaliy Yakovlevich',
#                                    'org': 'IP Khnykin Vitaliy Yakovlevich',
#                                },
#                                'country': {'countryname': 'Russia'},
#                                'city': {'cityname': ''},
#                                'geolocation': {'lat': 55.7386, 'lon': 37.6068},
#                            },
#                        },
#                        {
#                            'localportdetails': {'port': 33089, 'portname': 'Unknown'},
#                            'remoteipdetails': {
#                                'ipaddressv4': '92.63.194.74',
#                                'organization': {
#                                    'asn': '48817',
#                                    'asnorg': 'Chelyshev Sergej Aleksandrovich',
#                                    'isp': 'OOO Patent-Media',
#                                    'org': 'OOO Patent-Media',
#                                },
#                                'country': {'countryname': 'Ukraine'},
#                                'city': {'cityname': ''},
#                                'geolocation': {'lat': 50.45, 'lon': 30.5233},
#                            },
#                        },
#                    ],
#                    'blocked': False,
#                },
#            },
#            'resourcerole': 'TARGET',
#            'additionalinfo': {'threatname': 'Scanner', 'threatlistname': 'ProofPoint'},
#            'evidence': {'threatintelligencedetails': [{'threatnames': ['Scanner'], 'threatlistname': 'ProofPoint'}]},
#            'eventfirstseen': '2019-08-21T18:06:13Z',
#            'eventlastseen': '2019-08-21T20:34:12Z',
#            'archived': False,
#            'count': 3,
#        },
#    },
#    'timestamp': '2019-08-21T21:01:09.004000+00:00',
#    'utctimestamp': '2019-08-21T21:01:09.004000+00:00',
#    'hostname': 'i-00c19ca3bf7d2e7db',
#    'processname': 'guardduty',
#    'processid': '1337',
#    'summary': 'EC2 instance has an unprotected port which is being probed by a known malicious host.',
#    'category': 'Recon:EC2/PortProbeUnprotectedPort',
#    'type': 'event',
#    'source': 'guardduty',
# }


yy = {
    'Type': 'Notification',
    'MessageId': '01838ef7-f50f-5e26-bbe1-d8e7358f0004',
    'TopicArn': 'arn:aws:sns:us-east-1:371522382791:gd2md-GuardDutyEventNormalization-5HTB8BEL5Y1Q-SnsOutputTopic-1RHC5LI4J1UQK',
    'Message': '{"timestamp": "2019-10-04 03:36:32.399000", "hostname": "i-028858edc06f11624", "processname": "guardduty", "processid": 1337, "severity": "INFO", "summary": "EC2 instance has an unprotected port which is being probed by a known malicious host.", "category": "Recon:EC2/PortProbeUnprotectedPort", "source": "guardduty", "tags": ["PORT_PROBE"], "details": {"schemaVersion": "2.0", "accountId": "692406183521", "region": "us-west-2", "partition": "aws", "id": "a0b6ca682dd376625d7c7df5d543acde", "arn": "arn:aws:guardduty:us-west-2:692406183521:detector/90b4e5d7bef5a2adc076a62bd3d88c78/finding/a0b6ca682dd376625d7c7df5d543acde", "type": "Recon:EC2/PortProbeUnprotectedPort", "resource": {"resourceType": "Instance", "instanceDetails": {"instanceId": "i-028858edc06f11624", "instanceType": "c5.2xlarge", "launchTime": "2019-10-04T03:17:53Z", "platform": null, "productCodes": [], "iamInstanceProfile": null, "networkInterfaces": [{"ipv6Addresses": [], "networkInterfaceId": "eni-029db3da50ff8f792", "privateDnsName": "ip-10-144-42-207.us-west-2.compute.internal", "privateIpAddress": "10.144.42.207", "privateIpAddresses": [{"privateDnsName": "ip-10-144-42-207.us-west-2.compute.internal", "privateIpAddress": "10.144.42.207"}], "subnetId": "subnet-2eaaba67", "vpcId": "vpc-35df7053", "securityGroups": [{"groupName": "livelog-direct - gecko-workers", "groupId": "sg-09d6be73"}, {"groupName": "rdp-only - gecko-workers", "groupId": "sg-3bd7bf41"}], "publicDnsName": "ec2-54-184-220-129.us-west-2.compute.amazonaws.com", "publicIp": "54.184.220.129"}], "tags": [{"key": "Name", "value": "gecko-t-win10-64"}, {"key": "WorkerType", "value": "ec2-manager-production/gecko-t-win10-64"}, {"key": "Owner", "value": "ec2-manager-production"}], "instanceState": "running", "availabilityZone": "us-west-2b", "imageId": "ami-0941f5f392ca65e56", "imageDescription": "Gecko tester for Windows 10 64 bit; worker-type: gecko-t-win10-64, source: https://github.com/mozilla-releng/OpenCloudConfig/commit/c78696d, deploy: https://tools.taskcluster.net/tasks/EW5AzghSSn64LYlskZgjwg"}}, "severity": 2, "createdAt": "2019-10-04T03:29:05.958Z", "updatedAt": "2019-10-04T03:29:05.958Z", "title": "Unprotected port on EC2 instance i-028858edc06f11624 is being probed.", "description": "EC2 instance has an unprotected port which is being probed by a known malicious host.", "finding": {"serviceName": "guardduty", "detectorId": "90b4e5d7bef5a2adc076a62bd3d88c78", "action": {"actionType": "PORT_PROBE", "portProbeAction": {"portProbeDetails": [{"localPortDetails": {"port": 3389, "portName": "RDP"}, "remoteIpDetails": {"ipAddressV4": "92.119.160.80", "organization": {"asn": "49505", "asnOrg": "OOO Network of data-centers Selectel", "isp": "Mosnet LLC", "org": "Mosnet LLC"}, "country": {"countryName": "Russia"}, "city": {"cityName": ""}, "geoLocation": {"lat": 55.7386, "lon": 37.6068}}}], "blocked": false}}, "resourceRole": "TARGET", "additionalInfo": {"threatName": "Scanner", "threatListName": "ProofPoint"}, "evidence": {"threatIntelligenceDetails": [{"threatListName": "ProofPoint", "threatNames": ["Scanner"]}]}, "eventFirstSeen": "2019-10-04T03:24:39Z", "eventLastSeen": "2019-10-04T03:25:01Z", "archived": false, "count": 1}}}',
    'Timestamp': '2019-10-04T03:36:32.932Z',
    'SignatureVersion': '1',
    'Signature': 'haXZywBjzZtlJWcmRdj2hcAPtpmCjD4n/03EZgs+UI5UoVSEIAOPdBc/GZdobsHwGoS1ZWMQeo3NwsvQMJGHaugwTcSeCu9AK9ccLJP4G7dEMLp5AXGbpZ23e5bwRZPXTXhSTy1MOf31EIY6HQNrpKgsxV9HWsFUJC3RqNsopBMykeJPAN/fx8vgbVOBH+8WAKiXe2xUJCb5epQ4mlhTwGbLBhHTl+asfZLoSXhXBO84wVFuB9cpz/d2N4/wiCRxAblcj7Wq8q7/WnTD6I3UpRS+Tlb8iQd1XMiNijXGOU92fn0CQGk7HLCkPbmly5UqZWk08N3Zh7ek5GoWrAsdlQ==',
    'SigningCertURL': 'https://sns.us-east-1.amazonaws.com/SimpleNotificationService-6aad65c2f9911b05cd53efda11f913f9.pem',
    'UnsubscribeURL': 'https://sns.us-east-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-east-1:371522382791:gd2md-GuardDutyEventNormalization-5HTB8BEL5Y1Q-SnsOutputTopic-1RHC5LI4J1UQK:ce07f0eb-97cf-4d73-a683-24300507a3c3',
}

yyy = {
    "timestamp": "2019-10-04 03:36:32.399000",
    "hostname": "i-028858edc06f11624",
    "processname": "guardduty",
    "processid": 1337,
    "severity": "INFO",
    "summary": "EC2 instance has an unprotected port which is being probed by a known malicious host.",
    "category": "Recon:EC2/PortProbeUnprotectedPort",
    "source": "guardduty",
    "tags": ["PORT_PROBE"],
}
# dddddetails = {"schemaVersion": "2.0", "accountId": "692406183521", "region": "us-west-2", "partition": "aws", "id": "a0b6ca682dd376625d7c7df5d543acde", "arn": "arn:aws:guardduty:us-west-2:692406183521:detector/90b4e5d7bef5a2adc076a62bd3d88c78/finding/a0b6ca682dd376625d7c7df5d543acde", "type": "Recon:EC2/PortProbeUnprotectedPort", "resource": {"resourceType": "Instance", "instanceDetails": {"instanceId": "i-028858edc06f11624", "instanceType": "c5.2xlarge", "launchTime": "2019-10-04T03:17:53Z", "platform": null, "productCodes": [], "iamInstanceProfile": null, "networkInterfaces": [{"ipv6Addresses":[], "networkInterfaceId":"eni-029db3da50ff8f792", "privateDnsName":"ip-10-144-42-207.us-west-2.compute.internal", "privateIpAddress":"10.144.42.207", "privateIpAddresses":[{"privateDnsName":"ip-10-144-42-207.us-west-2.compute.internal", "privateIpAddress":"10.144.42.207"}], "subnetId":"subnet-2eaaba67", "vpcId":"vpc-35df7053", "securityGroups":[{"groupName":"livelog-direct - gecko-workers", "groupId":"sg-09d6be73"}, {"groupName":"rdp-only - gecko-workers", "groupId":"sg-3bd7bf41"}], "publicDnsName":"ec2-54-184-220-129.us-west-2.compute.amazonaws.com", "publicIp":"54.184.220.129"}], "tags": [{"key":"Name", "value":"gecko-t-win10-64"}, {"key":"WorkerType", "value":"ec2-manager-production/gecko-t-win10-64"}, {"key":"Owner", "value":"ec2-manager-production"}], "instanceState": "running", "availabilityZone": "us-west-2b", "imageId": "ami-0941f5f392ca65e56", "imageDescription": "Gecko tester for Windows 10 64 bit; worker-type: gecko-t-win10-64, source: https://github.com/mozilla-releng/OpenCloudConfig/commit/c78696d, deploy: https://tools.taskcluster.net/tasks/EW5AzghSSn64LYlskZgjwg"}}, "severity": 2, "createdAt": "2019-10-04T03:29:05.958Z", "updatedAt": "2019-10-04T03:29:05.958Z", "title": "Unprotected port on EC2 instance i-028858edc06f11624 is being probed.", "description": "EC2 instance has an unprotected port which is being probed by a known malicious host.", "finding": {"serviceName": "guardduty", "detectorId": "90b4e5d7bef5a2adc076a62bd3d88c78", "action": {"actionType": "PORT_PROBE", "portProbeAction": {"portProbeDetails": [{"localPortDetails":{"port":3389, "portName":"RDP"}, "remoteIpDetails":{"ipAddressV4":"92.119.160.80", "organization":{"asn":"49505", "asnOrg":"OOO Network of data-centers Selectel", "isp":"Mosnet LLC", "org":"Mosnet LLC"}, "country":{"countryName":"Russia"}, "city":{"cityName":""}, "geoLocation":{"lat":55.7386, "lon":37.6068}}}], "blocked": false}}, "resourceRole": "TARGET", "additionalInfo": {"threatName": "Scanner", "threatListName": "ProofPoint"}, "evidence": {"threatIntelligenceDetails": [{"threatListName":"ProofPoint", "threatNames":["Scanner"]}]}, "eventFirstSeen": "2019-10-04T03:24:39Z", "eventLastSeen": "2019-10-04T03:25:01Z", "archived": false, "count": 1}}}

t = {
    'Type': 'Notification',
    'MessageId': '7528642e-6e37-534d-96a8-323eace597ec',
    'TopicArn': 'arn:aws:sns:us-east-1:371522382791:gd2md-GuardDutyEventNormalization-5HTB8BEL5Y1Q-SnsOutputTopic-1RHC5LI4J1UQK',
    'Message': '{"timestamp": "2019-10-04 03:46:26.491000", "hostname": "i-05ed9f7efc559ef03", "processname": "guardduty", "processid": 1337, "severity": "INFO", "summary": "EC2 instance has an unprotected port which is being probed by a known malicious host.", "category": "Recon:EC2/PortProbeUnprotectedPort", "source": "guardduty", "tags": ["PORT_PROBE"], "details": {"schemaVersion": "2.0", "accountId": "692406183521", "region": "us-west-2", "partition": "aws", "id": "06b6c9a4dde988e5464ebf7fe8427522", "arn": "arn:aws:guardduty:us-west-2:692406183521:detector/90b4e5d7bef5a2adc076a62bd3d88c78/finding/06b6c9a4dde988e5464ebf7fe8427522", "type": "Recon:EC2/PortProbeUnprotectedPort", "resource": {"resourceType": "Instance", "instanceDetails": {"instanceId": "i-05ed9f7efc559ef03", "instanceType": "g3s.xlarge", "launchTime": "2019-10-03T17:58:54Z", "platform": null, "productCodes": [], "iamInstanceProfile": null, "networkInterfaces": [{"ipv6Addresses": [], "networkInterfaceId": "eni-0a4460c71bc4c6418", "privateDnsName": "ip-10-144-25-146.us-west-2.compute.internal", "privateIpAddress": "10.144.25.146", "privateIpAddresses": [{"privateDnsName": "ip-10-144-25-146.us-west-2.compute.internal", "privateIpAddress": "10.144.25.146"}], "subnetId": "subnet-d948b6bf", "vpcId": "vpc-35df7053", "securityGroups": [{"groupName": "livelog-direct - gecko-workers", "groupId": "sg-09d6be73"}, {"groupName": "rdp-only - gecko-workers", "groupId": "sg-3bd7bf41"}], "publicDnsName": "ec2-54-218-61-37.us-west-2.compute.amazonaws.com", "publicIp": "54.218.61.37"}], "tags": [{"key": "WorkerType", "value": "ec2-manager-production/gecko-t-win10-64-gpu-s"}, {"key": "Owner", "value": "ec2-manager-production"}, {"key": "Name", "value": "gecko-t-win10-64-gpu-s"}], "instanceState": "running", "availabilityZone": "us-west-2a", "imageId": "ami-036f90c73e6fd5387", "imageDescription": "Gecko tester for Windows 10 64 bit; worker-type: gecko-t-win10-64-gpu-s, source: https://github.com/mozilla-releng/OpenCloudConfig/commit/c78696d, deploy: https://tools.taskcluster.net/tasks/RCdbVWvgR42rSHZIjzlL4A"}}, "severity": 2, "createdAt": "2019-10-03T20:22:26.003Z", "updatedAt": "2019-10-04T03:28:59.817Z", "title": "Unprotected port on EC2 instance i-05ed9f7efc559ef03 is being probed.", "description": "EC2 instance has an unprotected port which is being probed by a known malicious host.", "finding": {"serviceName": "guardduty", "detectorId": "90b4e5d7bef5a2adc076a62bd3d88c78", "action": {"actionType": "PORT_PROBE", "portProbeAction": {"portProbeDetails": [{"localPortDetails": {"port": 3389, "portName": "RDP"}, "remoteIpDetails": {"ipAddressV4": "104.206.128.74", "organization": {"asn": "62904", "asnOrg": "Eonix Corporation", "isp": "Eonix Corporation", "org": "Eonix Corporation"}, "country": {"countryName": "United States"}, "city": {"cityName": "Las Vegas"}, "geoLocation": {"lat": 36.1214, "lon": -115.141}}}], "blocked": false}}, "resourceRole": "TARGET", "additionalInfo": {"threatName": "Scanner", "threatListName": "ProofPoint"}, "evidence": {"threatIntelligenceDetails": [{"threatNames": ["Scanner"], "threatListName": "ProofPoint"}]}, "eventFirstSeen": "2019-10-03T20:03:41Z", "eventLastSeen": "2019-10-04T03:14:52Z", "archived": false, "count": 7}}}',
    'Timestamp': '2019-10-04T03:46:26.856Z',
    'SignatureVersion': '1',
    'Signature': 'FjrpsdwEQwSS/ZRtGI/HR3mmql8g+pwizTwEEmcLPzlqm22FLUj1s+nR4rTNnB65CQ5hwOpK4jYC4lVDfUjzR9IY0dZLVIRLlWQIBLw5z3+59SEtA98fWA+uT6yAvyLANq6VxR6eQkF/Bz1lLErLBUUDaBkvMK0sv0TCYcJyhh333kujbl/G1v++e2RYbZET4F/YDiH6h9bcd2y1ntiGxEb8eqQWQ6XAlYjeGqqTgMPjNVxocvxu9hf1zSUDzD2ZJ3P8sk1d3/0699mP8XQbuBqOitAV6UXE1YhU6ME+D8QOow/eilJPZJKE9tNMxlsAgxJwOLYhTjfIdnBUEwAo1Q==',
    'SigningCertURL': 'https://sns.us-east-1.amazonaws.com/SimpleNotificationService-6aad65c2f9911b05cd53efda11f913f9.pem',
    'UnsubscribeURL': 'https://sns.us-east-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-east-1:371522382791:gd2md-GuardDutyEventNormalization-5HTB8BEL5Y1Q-SnsOutputTopic-1RHC5LI4J1UQK:ce07f0eb-97cf-4d73-a683-24300507a3c3',
}

m = {
    "timestamp": "2019-10-04 03:46:26.491000",
    "hostname": "i-05ed9f7efc559ef03",
    "processname": "guardduty",
    "processid": 1337,
    "severity": "INFO",
    "summary": "EC2 instance has an unprotected port which is being probed by a known malicious host.",
    "category": "Recon:EC2/PortProbeUnprotectedPort",
    "source": "guardduty",
    "tags": ["PORT_PROBE"],
    "details": {
        "schemaVersion": "2.0",
        "accountId": "692406183521",
        "region": "us-west-2",
        "partition": "aws",
        "id": "06b6c9a4dde988e5464ebf7fe8427522",
        "arn": "arn:aws:guardduty:us-west-2:692406183521:detector/90b4e5d7bef5a2adc076a62bd3d88c78/finding/06b6c9a4dde988e5464ebf7fe8427522",
        "type": "Recon:EC2/PortProbeUnprotectedPort",
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {
                "instanceId": "i-05ed9f7efc559ef03",
                "instanceType": "g3s.xlarge",
                "launchTime": "2019-10-03T17:58:54Z",
                "platform": null,
                "productCodes": [],
                "iamInstanceProfile": null,
                "networkInterfaces": [
                    {
                        "ipv6Addresses": [],
                        "networkInterfaceId": "eni-0a4460c71bc4c6418",
                        "privateDnsName": "ip-10-144-25-146.us-west-2.compute.internal",
                        "privateIpAddress": "10.144.25.146",
                        "privateIpAddresses": [
                            {
                                "privateDnsName": "ip-10-144-25-146.us-west-2.compute.internal",
                                "privateIpAddress": "10.144.25.146",
                            }
                        ],
                        "subnetId": "subnet-d948b6bf",
                        "vpcId": "vpc-35df7053",
                        "securityGroups": [
                            {"groupName": "livelog-direct - gecko-workers", "groupId": "sg-09d6be73"},
                            {"groupName": "rdp-only - gecko-workers", "groupId": "sg-3bd7bf41"},
                        ],
                        "publicDnsName": "ec2-54-218-61-37.us-west-2.compute.amazonaws.com",
                        "publicIp": "54.218.61.37",
                    }
                ],
                "tags": [
                    {"key": "WorkerType", "value": "ec2-manager-production/gecko-t-win10-64-gpu-s"},
                    {"key": "Owner", "value": "ec2-manager-production"},
                    {"key": "Name", "value": "gecko-t-win10-64-gpu-s"},
                ],
                "instanceState": "running",
                "availabilityZone": "us-west-2a",
                "imageId": "ami-036f90c73e6fd5387",
                "imageDescription": "Gecko tester for Windows 10 64 bit; worker-type: gecko-t-win10-64-gpu-s, source: https://github.com/mozilla-releng/OpenCloudConfig/commit/c78696d, deploy: https://tools.taskcluster.net/tasks/RCdbVWvgR42rSHZIjzlL4A",
            },
        },
        "severity": 2,
        "createdAt": "2019-10-03T20:22:26.003Z",
        "updatedAt": "2019-10-04T03:28:59.817Z",
        "title": "Unprotected port on EC2 instance i-05ed9f7efc559ef03 is being probed.",
        "description": "EC2 instance has an unprotected port which is being probed by a known malicious host.",
        "finding": {
            "serviceName": "guardduty",
            "detectorId": "90b4e5d7bef5a2adc076a62bd3d88c78",
            "action": {
                "actionType": "PORT_PROBE",
                "portProbeAction": {
                    "portProbeDetails": [
                        {
                            "localPortDetails": {"port": 3389, "portName": "RDP"},
                            "remoteIpDetails": {
                                "ipAddressV4": "104.206.128.74",
                                "organization": {
                                    "asn": "62904",
                                    "asnOrg": "Eonix Corporation",
                                    "isp": "Eonix Corporation",
                                    "org": "Eonix Corporation",
                                },
                                "country": {"countryName": "United States"},
                                "city": {"cityName": "Las Vegas"},
                                "geoLocation": {"lat": 36.1214, "lon": -115.141},
                            },
                        }
                    ],
                    "blocked": false,
                },
            },
            "resourceRole": "TARGET",
            "additionalInfo": {"threatName": "Scanner", "threatListName": "ProofPoint"},
            "evidence": {"threatIntelligenceDetails": [{"threatNames": ["Scanner"], "threatListName": "ProofPoint"}]},
            "eventFirstSeen": "2019-10-03T20:03:41Z",
            "eventLastSeen": "2019-10-04T03:14:52Z",
            "archived": false,
            "count": 7,
        },
    },
}

