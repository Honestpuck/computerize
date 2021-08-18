#! /usr/local/bin/python3
#
# groups v0.1
#
# Tony Williams 2021-08-09
#

"""See docstring for Managed class"""

import requests
from random import sample
import logging
import logging.handlers
import xml.etree.cElementTree as ET
from os import path
import plistlib
from collections import defaultdict
from pprint import pprint

APPNAME = "managed"
LOGLEVEL = logging.DEBUG
LOGFILE = "/usr/local/var/log/%s.log" % APPNAME
M_USERNAME = "honestpuck"  # name of jamf management user


class Managed:
    """
    Class to add management to the list of computers
    """

    def etree_to_dict(self, t):
        d = {t.tag: {} if t.attrib else None}
        children = list(t)
        if children:
            dd = defaultdict(list)
            for dc in map(self.etree_to_dict, children):
                for k, v in dc.items():
                    dd[k].append(v)
            d = {t.tag: {k: v[0] if len(v) == 1 else v for k, v in dd.items()}}
        if t.attrib:
            d[t.tag].update(("@" + k, v) for k, v in t.attrib.items())
        if t.text:
            text = t.text.strip()
            if children or t.attrib:
                if text:
                    d[t.tag]["#text"] = text
            else:
                d[t.tag] = text
        return d

    def _to_etree(self, d, root):
        if not d:
            pass
        elif isinstance(d, str):
            root.text = d
        elif isinstance(d, dict):
            for k, v in d.items():
                assert isinstance(k, str)
                if k.startswith("#"):
                    assert k == "#text" and isinstance(v, str)
                    root.text = v
                elif k.startswith("@"):
                    assert isinstance(v, str)
                    root.set(k[1:], v)
                elif isinstance(v, list):
                    for e in v:
                        self._to_etree(e, ET.SubElement(root, k))
                else:
                    self._to_etree(v, ET.SubElement(root, k))
        else:
            raise TypeError("invalid type: " + str(type(d)))

    def dict_to_etree(self, d):
        assert isinstance(d, dict) and len(d) == 1
        tag, body = next(iter(d.items()))
        node = ET.Element(tag)
        self._to_etree(body, node)
        return ET.tostring(node)

    def error(self, response, message):
        """ handle a requests error"""
        self.logger.error(message)
        self.logger.error(response.text)
        self.logger.error(response.status_code)
        self.logger.error(response.url)
        print(message)
        exit(1)

    def setup_logging(self):
        """Defines a nicely formatted logger"""
        self.logger = logging.getLogger(APPNAME)
        self.logger.setLevel(LOGLEVEL)
        handler = logging.handlers.TimedRotatingFileHandler(
            LOGFILE, when="D", interval=1, backupCount=7
        )
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        self.logger.addHandler(handler)

    def load_prefs(self):
        """ load the preferences from file """
        plist = path.expanduser(
            "~/Library/Preferences/com.github.nfr.autopkg.plist"
        )
        prefs = plistlib.load(open(plist, "rb"))
        self.url = prefs["JSS_URL"] + "/JSSResource/"
        self.hdrs = {"accept": "application/json"}

        # let's use the cookies to make sure we hit the
        # same server for every request.
        # The complication here is that ordinary and Premium Jamfers
        # get two DIFFERENT cookies for this.

        # the front page will give us the cookies
        r = requests.get(prefs["JSS_URL"])

        cookie_value = r.cookies.get("APBALANCEID")
        if cookie_value:
            # we are NOT premium Jamf Cloud
            self.cookies = dict(APBALANCEID=cookie_value)
        else:
            self.cookies = dict(AWSALB=r.cookies["AWSALB"])

        # now let's build a session
        self.sess = requests.Session()
        # self.sess.cookies = self.cookies
        self.sess.auth = (prefs["API_USERNAME"], prefs["API_PASSWORD"])
        self.logger.info("using cookies %s", self.sess.cookies)
        # we don't add the headers as we don't want JSON every time

    def get_computers(self):
        """ get a list of computers from the JSS """
        self.logger.info("getting computer list")
        r = self.sess.get(self.url + "computers", headers=self.hdrs)
        if r.status_code != 200:
            self.error(r, "unable to get computer list")
        return r.json()["computers"]

    def get_computer(self, id):
        """ get a single computer from the JSS """
        self.logger.info("getting computer %s", id)
        r = self.sess.get(self.url + "computers/id/%s" % id)
        if r.status_code != 200:
            self.error(r, "unable to get computer %s" % id)
        root = ET.fromstring(r.text)
        return self.etree_to_dict(root)

    def update_computer(self, json, idn):
        """ update a single computer in the JSS """
        self.logger.info("updating computer %s", idn)
        r = self.sess.put(
            self.url + "computers/id/%s" % idn,
            data=self.dict_to_etree(json),
        )
        if r.status_code != 201:
            self.error(r, "unable to update computer %s" % idn),
        return r.text

    def manage_computer(self, json):
        """ add management to one computer"""
        general = json["computer"]["general"]
        self.logger.info("managing computer %s", general["name"])
        print(f"managing computer ID: {general['id']} Name: {general["name"]})
        general["remote_management"]["managed"] = "true"
        general["remote_management"]["management_username"] = M_USERNAME
        general["remote_management"]["management_password_sha256"] = ""
        general["remote_management"]["management_password"] = "ChangeMe"
        general["supervised"] = "true"
        general["mdm_capable"] = "true"
        try:
            general["management_status"]["enrolled_via_dep"] = "true"
        except KeyError:
            general["management_status"] = {"enrolled_via_dep": "true"}
        general["management_status"]["user_approved_enrollment"] = "true"
        json["computer"]["general"] = general
        self.update_computer(json, general["id"])
        # return txt

    def main(self):
        """ main function """
        self.setup_logging()
        self.logger.info("*** starting %s", APPNAME)
        print("*** starting %s", APPNAME)
        self.load_prefs()

        for c in self.get_computers():
            json = self.get_computer(int(c["id"]))
            self.manage_computer(json)


if __name__ == "__main__":
    managed = Managed()
    managed.main()
