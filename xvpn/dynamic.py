"""
Ref: https://gist.github.com/pellaeon/3925b0fd2d8939e12b38325d16c0003b#file-spawn-gating-poc-py

Usage:
$ python3 dynamic.py com.security.xvpn.z35kb
"""

import frida
from frida_tools.application import Reactor
import threading

from ppadb.client import Client as AdbClient


import glob
import logging
import sys



logging.basicConfig(level=logging.DEBUG)

SERIAL = "01059c2b81b0d46a"

APP_PKG = sys.argv[1]  # "com.security.xvpn.z35kb"
logging.debug(APP_PKG)



class Dynamic:
    def __init__(self):
        self._stop_requested = threading.Event()
        self._reactor = Reactor(run_until_return=lambda _:
            self._stop_requested.wait())

        self._device = frida.get_usb_device(timeout=5)
        logging.debug("✔ enable_spawn_gating()")
        self._device.enable_spawn_gating()
        self._sessions = set()

        self._device.on("spawn-added", lambda child:
            self._reactor.schedule(
                lambda: self._on_delivered(child)))


    def run(self):
        self._reactor.schedule(lambda: self._start(APP_PKG))
        self._reactor.run()

    def _start(self, app_package_name):
        pid = self._device.spawn(app_package_name)
        logging.info("✔ spawn({})".format(app_package_name))
        self._instrument(pid)

    def _stop_if_idle(self):
        if len(self._sessions) == 0:
            self._stop_requested.set()


    def _instrument(self, pid):
        logging.info("✔ attach(pid={})".format(pid))
        session = self._device.attach(pid)
        session.on("detached", lambda reason:
            self._reactor.schedule(lambda:
                self._on_detached(pid, session, reason)))
        jscode = self.load_script()
        script = session.create_script(jscode)
        script.on("message", lambda message, data:
            self._reactor.schedule(
                lambda: self._on_message(pid, message, data)))
        script.load()
        logging.debug("✔ resume(pid={})".format(pid))
        self._device.resume(pid)
        self._sessions.add(session)


    def _on_delivered(self, child):
        logging.info("⚡ child-added: {}".format(child))
        if child.identifier.startswith(APP_PKG):
            self._instrument(child.pid)


    def _on_detached(self, pid, session, reason):
        logging.info("⚡ detached: pid={}, reason='{}'"
            .format(pid, reason))
        self._sessions.remove(session)
        self._reactor.schedule(self._stop_if_idle, delay=0.5)


    def _on_message(self, pid, message, data):
        # print("⚡ message: pid={}, payload={}"
        #     .format(pid, message["payload"]))
        # print("payload: ", message["payload"])
        # print("data: ", data)
        with open("log_"+APP_PKG+"_class.txt", "a") as f:
            f.write(message["payload"])



    def load_script(self):
        script = str()
        for file in glob.glob("./js/*.js"):
            logging.info("load " + file)
            with open(file, "r") as f:
                script += f.read()
        return script


dynamic = Dynamic()
dynamic.run()
