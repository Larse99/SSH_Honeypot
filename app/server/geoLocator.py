# GeoLocator
# This class locates the IP-adress and translates the IP to Country.
# The locator has a built-in cache, so the API doesn't get spammed.
# Author: Lars Eissink
# Github.com/Larse99

import requests
import json
import os

class geoLocator:
    def __init__(self, cacheFile='geocache.json'):
        self.cacheFile = cacheFile
        self.geoCache = self._loadCache()

    def _loadCache(self):
        if os.path.exists(self.cacheFile):
            try:
                with open(self.cacheFile, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                # If a file is corrupt, just return a empty list
                return {}
        return {}

    def _saveCache(self):
        try:
            with open(self.cacheFile, 'w') as f:
                json.dump(self.geoCache, f)
        except IOError:
            pass

    def _reloadCache(self):
        self.geoCache = self._loadCache()

    def getCountryName(self, ip):
        if not ip:
            return None
        
        # Check the local cache first
        if ip in self.geoCache:
            return self.geoCache[ip]
        
        try:
            response = requests.get(f'https://geolocation-db.com/json/{ip}').json()
            countryName = response.get('country_code')
            self.geoCache[ip] = countryName
            self._saveCache()
            self._reloadCache()

            return countryName
        except Exception:
            return None