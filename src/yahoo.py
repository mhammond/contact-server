#!/usr/bin/env python
#
# Contacts server front end
#
# The webserver module is responsible for incoming and outgoing HTTP requests.
#

import tornado.httpserver
import tornado.auth
import tornado.ioloop
import tornado.web
import os
import re
import time
import calendar
import base64
import traceback
import logging
import urllib
import cStringIO
import json
import cgi
import webconfig
import json
from urlparse import urlparse

import model  # replace this with a dbserver
import xmlreader


class YahooFetchHandler(tornado.web.RequestHandler, tornado.auth.OAuthMixin):
  _OAUTH_VERSION = "1.0"

  @tornado.web.asynchronous
  def get(self):
    uid = self.get_secure_cookie("uid")
    if not uid:
      logging.warn("No user session: redirecting to root")
      return self.redirect("/")

    args = {"count":"max", "format":"json"}
    page = self.get_argument("page", None)

    session = model.Session()
    user = model.user(session, uid)
    id = user.identity(session, model.OP_YAHOO)

    access_token = {"key":id.accessToken, "secret":id.accessSecret}
    url = "http://social.yahooapis.com/v1/user/" + id.opaqueID + "/contacts"
      
    if access_token:
        all_args = {}
        all_args.update(args)
        consumer_token = self._oauth_consumer_token()
        oauth = self._oauth_request_parameters(url, access_token, all_args, method="GET")
        args.update(oauth)

    if args: url += "?" + urllib.urlencode(args)
    callback = self.async_callback(self.onFetch)
    http = tornado.httpclient.AsyncHTTPClient()
    http.fetch(url, callback=callback)

  def _oauth_consumer_token(self):
      self.require_setting("yahoo_consumer_key", "Yahoo OAuth")
      self.require_setting("yahoo_consumer_secret", "yahoo OAuth")
      return dict(
          key=self.settings["yahoo_consumer_key"],
          secret=self.settings["yahoo_consumer_secret"])

  def onFetch(self, response):
    if response.code == 401: # need to reauthorize
      self.redirect("/authorize/yahoo?to=/fetch/yahoo")
    else:
      # Convert from GData XML to JSON:
      logging.error(response.body)
      doc = json.loads(response.body)
      logging.error(doc)
      result = {"status":"ok"}
      result["contacts"] = contacts = []

      anonCount = 1
      for aContact in doc["contacts"]["contact"]:
        try:
          person = {}
          contacts.append(person)
          for aField in aContact["fields"]:
            if aField["type"] == "name":
              name = person["name"] = {};
              if aField["value"]["givenName"]: name["givenName"] = aField["value"]["givenName"]
              if aField["value"]["familyName"]: name["familyName"] = aField["value"]["familyName"]
              if aField["value"]["middleName"]: name["middleName"] = aField["value"]["middleName"]
              if aField["value"]["prefix"]: name["prefix"] = aField["value"]["prefix"]
              if aField["value"]["suffix"]: name["suffix"] = aField["value"]["suffix"]

            elif aField["type"] == "phone":
              if not "phoneNumbers" in person: person["phoneNumbers"] = [];
              aPhone = {}
              aPhone["value"] = aField["value"];
              if aField["flags"] and len(aField["flags"]) > 0:
                aPhone["type"] = aField["flags"][0].lower()
              else:
                aPhone["type"] = "unlabeled"

              person["phoneNumbers"].append(aPhone)

            elif aField["type"] == "address":
              if not "addresses" in person: person["addresses"] = []
              anAddress = {}
              if aField["value"]["street"]: anAddress["streetAddress"] = aField["value"]["street"]
              if aField["value"]["city"]: anAddress["locality"] = aField["value"]["city"]
              if aField["value"]["stateOrProvince"]: anAddress["region"] = aField["value"]["stateOrProvince"]
              if aField["value"]["postalCode"]: anAddress["postalCode"] = aField["value"]["postalCode"]
              if aField["value"]["country"]: anAddress["country"] = aField["value"]["country"]
              if aField["value"]["countryCode"]: anAddress["countryCode"] = aField["value"]["countryCode"]
              if aField["flags"] and len(aField["flags"]) > 0:
                anAddress["type"] = aField["flags"][0].lower()
              else:
                anAddress["type"] = "unlabeled"

              person["addresses"].append(anAddress)

            elif aField["type"] == "email":
              if not "emails" in person: person["emails"] = []
              anEmail = {}
              anEmail["value"] = aField["value"]
              if aField["flags"] and len(aField["flags"]) > 0:
                anEmail["type"] = aField["flags"][0].lower()
              else:
                anEmail["type"] = "internet"

              person["emails"].append(anEmail)

            elif aField["type"] == "yahooid":
              if not "accounts" in person: person["accounts"] = []
              person["accounts"].append({"type":"yahoo", "username":aField["value"], "domain":"yahoo.com"})
            
            elif aField["type"] == "otherid":

              if aField["flags"] and len(aField["flags"]) > 0:
                flag = aField["flags"][0]
                domain = None
                type = None
                
                if flag == "GOOGLE":
                  domain = "google.com"
                  type = "google"
                elif flag == "ICQ":
                  domain = "icq.com"
                  type = "ICQ"
                elif flag == "JABBER":
                  domain = "jabber"
                  type = "Jabber"
                elif flag == "MSN":
                  domain = "msn.com"
                  type = "MSN"
                elif flag == "SKYPE":
                  domain = "skype.com"
                  type = "skype"
                else:
                  domain = flag.lower()
                  type = flag.lower()

                if not "accounts" in person: person["accounts"] = []
                person["accounts"].append({"type":type, "username":aField["value"], "domain":domain});

            elif aField["type"] == "link":

              if aField["flags"] and len(aField["flags"]) > 0:
                flag = aField["flags"][0]
                type = flag.lower();

                if not "urls" in person: person.urls = []
                person["urls"].push({"type":type, "value":aField["value"]})
            elif aField["type"] == "company":

              if not person["organizations"]: person["organizations"] = [{}]
              person["organizations"][0].name = aField["value"];

            elif aField["type"] == "jobTitle":
              if not person["organizations"]:person["organizations"] = [{}]
              person["organizations"][0]["title"] = aField["value"];

            # Construct a display name:
            if "name" in person:
              if "givenName" in person["name"] and "familyName" in person["name"]:
                person["displayName"] = person["name"]["givenName"] + " " + person["name"]["familyName"] # FIXME Eurocentric
              elif "givenName" in person["name"]:
                person["displayName"] = person["name"]["givenName"]
              elif "familyName" in person["name"]:
                person["displayName" ]= person["name"]["familyName"]

#            if not person["displayName"] and person["accounts"]:
#              for p in person["accounts"]:
#                if p["domain"] == "yahoo.com":
#                  person["displayName"] = p["username"]
#                  break

#            if not person["displayName"]: person["displayName"] = person["accounts"][0]["username"]
#            if not person["displayName"] and person["emails"]:
#              person["displayName"] = person.emails[0]["value"];
#          }
#          if (!person.displayName) {
#            person.displayName = "Unnamed Yahoo Contact " + anonCount;
#            anonCount += 1;
#          }


        except Exception, e:
          logging.exception(e)
          pass
      self.write(json.dumps(result))
      self.finish()

#        
#          // Construct a display name:
#          if (person.name) {
#            if (person.name.givenName && person.name.familyName) {
#              person.displayName = person.name.givenName + " " + person.name.familyName; // FIXME Eurocentric
#            } else if (person.name.givenName) {
#              person.displayName = person.name.givenName;
#            } else if (person.name.familyName) {
#              person.displayName = person.name.familyName;            
#            }
#          } else {
#            person.name = {givenName:"", familyName:""};
#          }
#          
#          if (!person.displayName && person.accounts) {
#            for each (p in person.accounts) {
#              if (p.domain == "yahoo.com") {
#                person.displayName = p.username;
#                break;
#              }
#            }
#            if (!person.displayName) person.displayName = person.accounts[0].username;
#          }
#          if (!person.displayName && person.emails) {
#            person.displayName = person.emails[0]["value"];
#          }
#          if (!person.displayName) {
#            person.displayName = "Unnamed Yahoo Contact " + anonCount;
#            anonCount += 1;
#          }
#          people.push(person);
#        } catch (e) {
#          this._log.info("Error importing Yahoo contact: " + e);
#        }
#      }#


#      self.write(json.dumps(result))
#      self.finish()
      
