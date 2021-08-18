#! /usr/local/bin/python3
#
# sanitise v0.1
#
# Tony Williams 2021-08-09
#

"""See docstring for Sanitiser class"""

import requests
from random import randint, choice
import logging
import logging.handlers
import xml.etree.cElementTree as ET
from os import path
import plistlib

APPNAME = "sanitise"
LOGLEVEL = logging.DEBUG
LOGFILE = "/usr/local/var/log/%s.log" % APPNAME


class Data:
    def __init__(self):
        self.surnames = self.surname()
        self.names = self.name()

    def surnames():
        with open("surnames.txt", "r") as f:
            surname = f.read().splitlines()
        return surname

    def names():
        with open("names.txt", "r") as f:
            name = f.read().splitlines()
        return name

    # a blank line at the file end can cause problems so use len - 1 in case it's there
    def random_surname():
        surnames = Data.surnames()
        surname = surnames[randint(0, len(surnames) - 1)]
        return surname

    def random_name():
        names = Data.names()
        name = names[randint(0, len(names) - 1)]
        return name

    def random_name_surname():
        name = Data.random_name()
        surname = Data.random_surname()
        return (name, surname)

    def random_with_N_digits(n):
        range_start = 10 ** (n - 1)
        range_end = (10 ** n) - 1
        return str(randint(range_start, range_end))

    def random_with_N_chars(n):
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return "".join(choice(chars) for x in range(n))

    def random_userid():
        return "ID" + Data.random_with_N_digits(6)

    def random_phone():
        return "+6128" + Data.random_with_N_digits(7)

    def random_serial():
        # using "C02V" as a prefix to look more real
        return "C02V" + Data.random_with_N_chars(8)


class Sanitiser:
    def setup_logging(self):
        """Defines a nicely formatted logger"""

        self.logger = logging.getLogger(APPNAME)
        self.logger.setLevel(LOGLEVEL)
        # we may be the second and subsequent iterations of JPCImporter
        # and already have a handler.
        if len(self.logger.handlers) > 0:
            return
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
        # Which pref format to use, autopkg or jss_importer
        autopkg = True
        if autopkg:
            plist = path.expanduser(
                "~/Library/Preferences/com.github.nfr.autopkg.plist"
            )
            prefs = plistlib.load(open(plist, "rb"))
            self.url = prefs["JSS_URL"] + "/JSSResource/computers"
            self.auth = (prefs["API_USERNAME"], prefs["API_PASSWORD"])
        else:
            plist = path.expanduser("~/Library/Preferences/JPCImporter.plist")
            prefs = plistlib.load(open(plist, "rb"))
            self.url = prefs["url"]
            self.auth = (prefs["user"], prefs["password"])
        self.hdrs = {"accept": "application/json"}

    def one_record(self, record):
        root = ET.fromstring(record)

        serial = Data.random_serial()
        root.find("general/name").text = "MB" + serial
        root.find("general/serial_number").text = serial
        root.find("location/username").text = Data.random_userid()
        name, surname = Data.random_name_surname()
        root.find("location/realname").text = name + " " + surname
        root.find("location/real_name").text = name + " " + surname
        root.find("location/email_address").text = (
            name + "." + surname + "@example.com"
        )
        phone = Data.random_phone()
        root.find("location/phone").text = phone
        root.find("location/phone_number").text = phone
        return ET.tostring(root)

    def loop_records(self):
        response = requests.get(self.url, auth=self.auth, headers=self.hdrs)
        if response.status_code == 200:
            records = response.json()["computers"]
            for record in records:
                print("Starting record id: %s" % record["id"])
                response = requests.get(
                    self.url + "/id/%s" % record["id"], auth=self.auth
                )
                if response.status_code == 200:
                    new_record = self.one_record(response.text)
                    self.logger.info("Updating record %s", record["id"])
                    response = requests.put(
                        self.url + "/id/%s" % record["id"],
                        auth=self.auth,
                        data=new_record,
                    )
                    next
                    if response.status_code != 201:
                        self.logger.error(
                            "Error updating record %s", record["id"]
                        )
                        self.logger.error(response.text)
                        response = requests.delete(
                            self.url + "/id/%s" % record["id"], auth=self.auth
                        )
                        print(
                            f"Deleted {record['id']} status code: {response.status_code}"
                        )
                else:
                    self.logger.error("Error getting record %s", record["id"])
                    self.logger.error(response.text)
                    raise Exception("Error getting record %s", record["id"])
        else:
            self.logger.error("Error getting records")
            self.logger.error(response.text)
            raise Exception("Error getting records")

    def main(self):
        self.setup_logging()
        self.load_prefs()
        self.loop_records()


if __name__ == "__main__":
    Sanitiser().main()
