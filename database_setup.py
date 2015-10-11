from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
	__tablename__ = 'user'

	name = Column(String(250), nullable=False)
	id = Column(Integer, primary_key=True)
	email = Column(String(250))
	picture = Column(String(250))

	@property
	def serialize(self):
		"""Return object data in easily serializeable format"""
		return {
			'name'          : self.name,
			'id'            : self.id,
			'picture'       : self.picture,
			'email'         : self.email,
		}

class Place(Base):
	__tablename__ = 'place'

	name = Column(String(250), nullable=False)
	id = Column(Integer, primary_key=True)
	user_id = Column(Integer,ForeignKey('user.id'))
	user = relationship(User)

	@property
	def serialize(self):
		"""Return object data in easily serializeable format"""
		return {
			'name'          : self.name,
			'id'            : self.id,
		}

class Thing(Base):
	__tablename__ = 'thing'

	name =Column(String(80), nullable = False)
	id = Column(Integer, primary_key = True)
	description = Column(String(250))
	kind_of_thing = Column(String(250))
	image = Column(String(250))
	place_id = Column(Integer,ForeignKey('place.id'))
	place = relationship(Restaurant)
	user_id = Column(Integer,ForeignKey('user.id'))
	user = relationship(User)

	@property
	def serialize(self):
		"""Return object data in easily serializeable format"""
		return {
			'name'          : self.name,
			'id'            : self.id,
			'description'   : self.description,
			'kind_of_thing' : self.course,
		}

engine = create_engine('sqlite:///thingsyouseeallover.db')

Base.metadata.create_all(engine)