# Database model for dbserver

import logging
import re
import os
import subprocess
import simplejson as json
from datetime import datetime

import sqlalchemy
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Unicode, DateTime, Column, MetaData, Integer, Text, Boolean, String
from dbconfig import engine, Session
import sqlalchemy.exc
from sqlalchemy.orm.exc import NoResultFound

# SQLAlchemy setup:
metadata = MetaData(engine)
Base = declarative_base(metadata=metadata)

# A provider of contacts
class Provider(Base):
    __tablename__ = "identities"

    id = Column(Integer, primary_key=True)
    provider = Column(Integer)
    accessToken = Column(Text)  # these are sometimes really big!  using Text to be safe.
    accessSecret = Column(Text)
    verifiedDate = Column(DateTime)
    user_id = Column(Integer)

    def __init__(self, user_id, providerID):
      self.user_id = user_id
      self.provider = providerID

    def __repr__(self):
      return "<Identity(%d, %s)>" % (self.id, self.user_id)

    def verifiedNow(self):
      self.verifiedDate = datetime.now()


# Object Person
class Person(Base):      
    __tablename__ = "person"
    
    id = Column(Integer, primary_key=True)
    displayName = Column(Text, nullable=False)          # if any
    profile = Column(Text)                              # this is the JSON blob
    primary = Column(Boolean, default=False)            # if True, this Person represents its Owner
    owner_id = Column(Integer) # logically a ForeignKey("users.id"))
    updated = Column(DateTime)
    # TODO perhaps a thumbnail URL?
    # email indexing will require another table.
    
    def __init__(self, isPrimary, displayName, profile, ownerid, updated):
      self.displayName = displayName
      self.profile = profile
      self.primary = isPrimary
      self.owner_id = ownerid
      self.updated = updated
    
    def __repr__(self):
      return "<Person(%d, %s, %s, %s)>" % (self.id, self.name, self.primary, self.profile)


# If this is our first run, go take care of housekeeping
metadata.create_all(engine) 

def user_provider(session, uid, provider_id):
  try:
    return session.query(Provider).filter(Provider.user_id == uid).filter(Provider.provider == provider_id).one()
  except NoResultFound:
    return None

def all_user_providers(session, uid):
  return session.query(Provider).filter(Provider.user_id == uid).all()

def person(session, id, userid):
  return session.query(Person).filter(owner_id == userid).filter(id == id).first()

def persons_displayNames(session, userid):
  return session.query(Person).filter(Person.owner_id == userid).all()
    
def createPerson(session, isPrimary, displayName, profile, userid):
  try:
    p = Person(isPrimary, displayName, profile, userid, datetime.now())
    session.add(p)
    session.commit()
    return p

  except sqlalchemy.exc.IntegrityError, e:
    session.rollback()
    raise ValueError("Error while creating person (%s)" % e)
