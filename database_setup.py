# Provides objects and variables to manipulate the project runtime environment

# Provides objects and variables to manipulate the project runtime environment

import sys

# Object relational mapping
from sqlalchemy import Column, ForeignKey, Integer, String, NVARCHAR
# Added NVARCHAR to fix Unicode problem for Irish Names with fadas


# To create instance of the class called declarative base to import SQL Alchemy Features
from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy.orm import relationship

from sqlalchemy import create_engine

DATA_BACKEND = 'cloudsql'
CLOUDSQL_USER = 'marc'
CLOUDSQL_PASSWORD = '7Ggda0dqaD0ovIIu'
CLOUDSQL_DATABASE = 'offerings'

CLOUDSQL_CONNECTION_NAME = 'pycharm-194111:europe-west2:babiesgrowdatabase'

# Create instance
Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(NVARCHAR(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Offering(Base):
    __tablename__ = 'offering'

    id = Column(Integer, primary_key=True )
    title = Column(String(300), nullable=False)
    date = Column(String(300), nullable=False)
    location = Column(String(300), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    file = relationship('File')
    tag = relationship('Tag')
    comment = relationship('Comment')



    @property
    def serialize(self):
        #Return objects in serializable form
        return {
            'id': self.id,
            'title': self.title,
            'date': self.date,
            'location': self.location,

        }



class Tag(Base):
    __tablename__ = 'tag'

    id = Column(Integer, primary_key=True)
    tag_name = Column(String(300), nullable=False)
    offering_id = Column(Integer, ForeignKey('offering.id'), nullable=True)
    offering = relationship(Offering)


    @property
    def serialize(self):
        # Return objects in serializable form
        return {
            'id': self.id,
            'name': self.tag_name,

        }


class Comment(Base):
    __tablename__ = 'comment'

    id = Column(Integer, primary_key=True)
    body = Column(String(1000), nullable=False)
    offering_id = Column(Integer, ForeignKey('offering.id'), nullable=True)
    offering = relationship(Offering)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        # Return objects in serializable form
        return {
            'id': self.id,
            'body': self.body,

        }

class File(Base):
    __tablename__ = 'file'

    id = Column(Integer, primary_key=True)
    image = Column(String(250))
    offering_id = Column(Integer, ForeignKey('offering.id'))
    offering = relationship(Offering)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)



    @property
    def serialize(self):
        # Return objects in serializable form
        return {
            'id': self.id,
            'image': self.image,

        }


# Engine instance with a mysql database
engine = create_engine('mysql+pymysql://root:7Ggda0dqaD0ovIIu@/offerings?unix_socket=/cloudsql/pycharm-194111:europe-west2:babiesgrowdatabase')



#For testing locally with Cloud SQL Proxy
#'mysql+pymysql://marc:password@127.0.0.1:8000/offerings'

# Goes into database and creates the tables
Base.metadata.create_all(engine)
