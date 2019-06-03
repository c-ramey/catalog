from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db_setup import Base, User, Category, Item

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()

# create myself as a user
User1 = User(name="Cr2712", email="cr2712@gmail.com")
session.add(User1)
session.commit()

# Cornhole category
category1 = Category(user_id=1, name="Cornhole", description = "Corhhole is a sport I love")

session.add(category1)
session.commit()

cornhole_item1 = Item(user_id=1, name="Cornhole boards", description="These are cornhole boards", category=category1)

session.add(cornhole_item1)
session.commit()

print "Good job...database records created."
