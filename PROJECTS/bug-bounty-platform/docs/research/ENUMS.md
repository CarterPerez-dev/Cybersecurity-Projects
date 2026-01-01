
SQLAlchemy Enums - Careful what goes into the database
Will Rouesnel 2024-04-25 21:54
The Situation
SQLAlchemy is an obvious choice when you need to throw together anything dealing with databases in Python. There might be other options, there might be faster options, but if you need it done then SQLAlchemy will do it for you pretty well and very ergonomically.

The problem I ran into recently is dealing with Python enums recently. Or more specifically: I had a user input problem which obviously turned into an enum application side - I had a limited set of inputs I wanted to allow, because those were what we supported - and I didn't want strings all through my code testing for values.

So on the client side it's obvious: check if the string matches an enum value, and use that. The enum would look something like below:

from enum import Enum

class Color(Enum):
    RED = "red"
    GREEN = "green"
    BLUE = "blue"
Now from this, we have our second problem: storing this in the database. We want to not do work here - that's we're using SQLAlchemy, so we can have our commmon problems handled. And so, SQLAlchemy helps us - here's automatic enum type handling for us.

Easy - so our model using the declarative syntax, and typehints can be written as follows:

import sqlalchemy
from sqlalchemy.orm import Mapped, DeclarativeBase, Session, mapped_column
from sqlalchemy import create_engine, select, text

class Base(DeclarativeBase):
    pass

class TestTable(Base):
    __tablename__ = "test_table"
    id: Mapped[int] = mapped_column(primary_key=True)
    value: Mapped[Color]
This is essentially identical to the documentation we see above. And, if we run this in a sample program - it works!

engine = create_engine("sqlite://")

Base.metadata.create_all(engine)

with Session(engine) as session:
    # Create normal values
    for enum_item in Color:
        session.add(TestTable(value=enum_item))
    session.commit()

# Now try and read the values back
with Session(engine) as session:
    records = session.scalars(select(TestTable)).all()
    for record in records:
        print(record.value)
Color.RED
Color.GREEN
Color.BLUE
Right? We stored some enum's to the database and retreived them in simple elegant code. This is exactly what we want...right?

But the question is...what did we actually store? Let's extend the program to do a raw query to read back that table...

from sqlalchemy import text

with engine.connect() as conn:
    print(conn.execute(text("SELECT * FROM test_table;")).all())
[(1, 'RED'), (2, 'GREEN'), (3, 'BLUE')]
Notice the tuples: the second column, we see "RED", "GREEN" and "BLUE"...but our enum defines our colors as RED is "red". What's going on? And is something wrong here?

Depending how you view the situation, yes, but also no - but it's likely this isn't what you wanted either.

The primary reason to use SQLAlchemy enum types is to take advantage of something like PostgreSQL supporting native enum types in the database. Everywhere else in SQLAlchemy, when we define a python class - like we do with TestTable above - we're not defining a Python object, we're defining a Python object which is describing the database objects we want and how they'll behave.

And so long as we're using things that come from SQLAlchemy - and under-the-hood SQLAlchemy is converting that enum.Enum to sqlalchemy.Enum - then this makes complete sense. The enum we declare is declaring what values we store, and what data value they map too...in the sense that we might use the data elsewhere, in our application. Basically our database will hold the symbolic value RED and we interpret that as meaning "red" - but we reserve the right to change that interpretation.

But if we're coming at this from a Python application perspective - i.e. the reason we made an enum - we likely have a different view of the problem. We're thinking "we want the data to look a particular way, and then to refer to it symbolically in code which we might change" - i.e. the immutable element is the data, the value, of the enum - because that's what we'll present to the user, but not what we want to have all over the application.

In isolation these are separate problems, but automatic enum handling makes the boundary here fuzzy: because while the database is defined in our code, from one perspective, it's also external to it - i.e. we may be writing code which is meant to simply interface with and understand a database not under our control. Basically, the enum.Enum object feels like it's us saying "this is how we'll interpret the external world" and not us saying "this is what the database looks like".

And in that case then, our view of what the enum is is probably more like "the enum is the internal symbolic representation of how we plan to consume database values" - i.e. we expect to map "red" to Color.RED from the database. Rather then reading the database and interpreting RED as "red".

Nobodies wrong - but you probably have your assumptions going into this (I know I did...but it compiled, it worked, and I never questioned it - and so long as I'm the sole owner, who cares right?)

The Problem
There are a few problems though with this interpretation. One is obvious: we're a simple, apparently safe refactor away from ruining our database schema and we might be aware of it. In the above, naive interpretation, changing Color.RED to Color.LEGACY_RED for example, is implying that RED is no longer a valid value in the database - which if we think of the enum as an application mapping to an external interface is something which might make sense.

This is the sort of change which crops up all the time. We know the string "red" is out there, hardcoded and compiled into a bunch of old systems so we can't just go and change a color name in the database. Or we're doing rolling deployments and we need consistency of values - or share the database or any number of other complex environment concerns. Either way: we want to avoid needlessly updating the database value - changing our code, but not an apparent variable constant - should be safe.

However we're not storing the data we think we are. We expected "red", "green" and "blue" and got "RED", "GREEN" and "BLUE". It's worth noting that the SQLAlchemy documentation leads you astray like this, since the second example showing using typing.Literal for the mapping uses the string assignments from the first (and neither shows a sample table result which makes it obvious on a quick read).

If we change a name in this enum, then the result is actually bad if we've used it anywhere - we stop being able to read models out of this table at all. So if we do the following:

class Color(Enum):
    LEGACY_RED = "red"
    GREEN = "green"
    BLUE = "blue"
Then try to read the models we've created, it won't work - in fact we can't read any part of that table anymore (this post is written as a Jupyter notebook so the redefinition below is needed to setup the SQLAlchemy model again)

class Base(DeclarativeBase):
    pass

class TestTable(Base):
    __tablename__ = "test_table"
    id: Mapped[int] = mapped_column(primary_key=True)
    value: Mapped[Color]

with Session(engine) as session:
    records = session.scalars(select(TestTable)).all()
    for record in records:
        print(record.value)
---------------------------------------------------------------------------
KeyError                                  Traceback (most recent call last)
~/.local/lib/python3.10/site-packages/sqlalchemy/sql/sqltypes.py in _object_value_for_elem(self, elem)
   1608         try:
-> 1609             return self._object_lookup[elem]
   1610         except KeyError as err:

KeyError: 'RED'

The above exception was the direct cause of the following exception:

LookupError                               Traceback (most recent call last)
/tmp/ipykernel_69447/1820198460.py in <module>
      8 
      9 with Session(engine) as session:
---> 10     records = session.scalars(select(TestTable)).all()
     11     for record in records:
     12         print(record.value)

~/.local/lib/python3.10/site-packages/sqlalchemy/engine/result.py in all(self)
   1767 
   1768         """
-> 1769         return self._allrows()
   1770 
   1771     def __iter__(self) -> Iterator[_R]:

~/.local/lib/python3.10/site-packages/sqlalchemy/engine/result.py in _allrows(self)
    546         make_row = self._row_getter
    547 
--> 548         rows = self._fetchall_impl()
    549         made_rows: List[_InterimRowType[_R]]
    550         if make_row:

~/.local/lib/python3.10/site-packages/sqlalchemy/engine/result.py in _fetchall_impl(self)
   1674 
   1675     def _fetchall_impl(self) -> List[_InterimRowType[Row[Any]]]:
-> 1676         return self._real_result._fetchall_impl()
   1677 
   1678     def _fetchmany_impl(

~/.local/lib/python3.10/site-packages/sqlalchemy/engine/result.py in _fetchall_impl(self)
   2268             self._raise_hard_closed()
   2269         try:
-> 2270             return list(self.iterator)
   2271         finally:
   2272             self._soft_close()

~/.local/lib/python3.10/site-packages/sqlalchemy/orm/loading.py in chunks(size)
    217                     break
    218             else:
--> 219                 fetch = cursor._raw_all_rows()
    220 
    221             if single_entity:

~/.local/lib/python3.10/site-packages/sqlalchemy/engine/result.py in _raw_all_rows(self)
    539         assert make_row is not None
    540         rows = self._fetchall_impl()
--> 541         return [make_row(row) for row in rows]
    542 
    543     def _allrows(self) -> List[_R]:

~/.local/lib/python3.10/site-packages/sqlalchemy/engine/result.py in <listcomp>(.0)
    539         assert make_row is not None
    540         rows = self._fetchall_impl()
--> 541         return [make_row(row) for row in rows]
    542 
    543     def _allrows(self) -> List[_R]:

lib/sqlalchemy/cyextension/resultproxy.pyx in sqlalchemy.cyextension.resultproxy.BaseRow.__init__()

lib/sqlalchemy/cyextension/resultproxy.pyx in sqlalchemy.cyextension.resultproxy._apply_processors()

~/.local/lib/python3.10/site-packages/sqlalchemy/sql/sqltypes.py in process(value)
   1727                 value = parent_processor(value)
   1728 
-> 1729             value = self._object_value_for_elem(value)
   1730             return value
   1731 

~/.local/lib/python3.10/site-packages/sqlalchemy/sql/sqltypes.py in _object_value_for_elem(self, elem)
   1609             return self._object_lookup[elem]
   1610         except KeyError as err:
-> 1611             raise LookupError(
   1612                 "'%s' is not among the defined enum values. "
   1613                 "Enum name: %s. Possible values: %s"

LookupError: 'RED' is not among the defined enum values. Enum name: color. Possible values: LEGACY_RED, GREEN, BLUE
Even though we did a proper refactor, we can no longer read this table - in fact we can't even read part of it without using raw SQL and giving up on our models entirely. Obviously if we were writing an application, we've just broken all our queries - but not because we messed anything up, but because we thought we were making a code change when in reality we were making a data change.

This behavior also makes it pretty much impossible to handle externally managed schemas or existing schemas - we don't really want our enum to have to follow someone else's data scheme, even if they're well behaved.

Finally it also hightlights another danger we've walked into: what if we try to read this column, and there are values there we don't recognize? We would also get the same error - in this case, RED is unknown because we removed it. But if a new version of our application comes along and has inserted ORANGE then we'd also have the same problem - we've lost backwards and forwards compatibility, in a way which doesn't necessarily show up easily. There's just no easy way to deal with these LookupError validation problems when we're loading large chunks of models - they happen at the wrong part of the stack

The Solution
Doing the obvious thing here got us a working applications with a bunch of technical footguns - which is unfortunate, but it does work. There are plenty of situations where we'd never encounter these though - although many more where we might. So what should we do instead?

To get the behavior we expected when we used an enum we can do the following in our model definition:

class Base(DeclarativeBase):
    pass

class TestTable(Base):
    __tablename__ = "test_table"
    id: Mapped[int] = mapped_column(primary_key=True)
    value: Mapped[Color] = mapped_column(sqlalchemy.Enum(Color, values_callable=lambda t: [ str(item.value) for item in t ]))
Notice the values_callable parameter. The order returned here should be the order our enum returns (and it is - it's simply passed our Enum object) - and returns the list of values which should be assigned in the database for it. In this case we simply do a Python string conversion of the enum value (which will just return the literal string - but if you were doing something ill-advised like mixing in numbers, then this makes it sensible for the DB).

When we run this with a new database, we now see that we get what we expected in the underlying table:

engine = create_engine("sqlite://")

Base.metadata.create_all(engine)

with Session(engine) as session:
    # Create normal values
    for enum_item in Color:
        session.add(TestTable(value=enum_item))
    session.commit()

# Now try and read the values back
with Session(engine) as session:
    records = session.scalars(select(TestTable)).all()
    print("We restored the following values in code...")
    for record in records:
        print(record.value)

print("But the underlying table contains...")
with engine.connect() as conn:
    print(conn.execute(text("SELECT * FROM test_table;")).all())
We restored the following values in code...
Color.LEGACY_RED
Color.GREEN
Color.BLUE
But the underlying table contains...
[(1, 'red'), (2, 'green'), (3, 'blue')]
Perfect. Now if we're connecting to an external database, or a schema we don't control, everything works great. But what about when we have unknown values? What happens then? Well we haven't fixed that, but we're much less likely to encounter it by accident now. Of course it's worth noting, SQLAlchemy also doesn't validate the inputs we put into this model against the enum before we write it either. So if we do this, then we're back to it not working:

with Session(engine) as session:
    session.add(TestTable(value="reed"))
    session.commit()
# Now try and read the values back
with Session(engine) as session:
    records = session.scalars(select(TestTable)).all()
    print("We restored the following values in code...")
    for record in records:
        print(record.value)
---------------------------------------------------------------------------
KeyError                                  Traceback (most recent call last)
~/.local/lib/python3.10/site-packages/sqlalchemy/sql/sqltypes.py in _object_value_for_elem(self, elem)
   1608         try:
-> 1609             return self._object_lookup[elem]
   1610         except KeyError as err:

KeyError: 'reed'

The above exception was the direct cause of the following exception:

LookupError                               Traceback (most recent call last)
/tmp/ipykernel_69447/3460624042.py in <module>
      1 # Now try and read the values back
      2 with Session(engine) as session:
----> 3     records = session.scalars(select(TestTable)).all()
      4     print("We restored the following values in code...")
      5     for record in records:

~/.local/lib/python3.10/site-packages/sqlalchemy/engine/result.py in all(self)
   1767 
   1768         """
-> 1769         return self._allrows()
   1770 
   1771     def __iter__(self) -> Iterator[_R]:

~/.local/lib/python3.10/site-packages/sqlalchemy/engine/result.py in _allrows(self)
    546         make_row = self._row_getter
    547 
--> 548         rows = self._fetchall_impl()
    549         made_rows: List[_InterimRowType[_R]]
    550         if make_row:

~/.local/lib/python3.10/site-packages/sqlalchemy/engine/result.py in _fetchall_impl(self)
   1674 
   1675     def _fetchall_impl(self) -> List[_InterimRowType[Row[Any]]]:
-> 1676         return self._real_result._fetchall_impl()
   1677 
   1678     def _fetchmany_impl(

~/.local/lib/python3.10/site-packages/sqlalchemy/engine/result.py in _fetchall_impl(self)
   2268             self._raise_hard_closed()
   2269         try:
-> 2270             return list(self.iterator)
   2271         finally:
   2272             self._soft_close()

~/.local/lib/python3.10/site-packages/sqlalchemy/orm/loading.py in chunks(size)
    217                     break
    218             else:
--> 219                 fetch = cursor._raw_all_rows()
    220 
    221             if single_entity:

~/.local/lib/python3.10/site-packages/sqlalchemy/engine/result.py in _raw_all_rows(self)
    539         assert make_row is not None
    540         rows = self._fetchall_impl()
--> 541         return [make_row(row) for row in rows]
    542 
    543     def _allrows(self) -> List[_R]:

~/.local/lib/python3.10/site-packages/sqlalchemy/engine/result.py in <listcomp>(.0)
    539         assert make_row is not None
    540         rows = self._fetchall_impl()
--> 541         return [make_row(row) for row in rows]
    542 
    543     def _allrows(self) -> List[_R]:

lib/sqlalchemy/cyextension/resultproxy.pyx in sqlalchemy.cyextension.resultproxy.BaseRow.__init__()

lib/sqlalchemy/cyextension/resultproxy.pyx in sqlalchemy.cyextension.resultproxy._apply_processors()

~/.local/lib/python3.10/site-packages/sqlalchemy/sql/sqltypes.py in process(value)
   1727                 value = parent_processor(value)
   1728 
-> 1729             value = self._object_value_for_elem(value)
   1730             return value
   1731 

~/.local/lib/python3.10/site-packages/sqlalchemy/sql/sqltypes.py in _object_value_for_elem(self, elem)
   1609             return self._object_lookup[elem]
   1610         except KeyError as err:
-> 1611             raise LookupError(
   1612                 "'%s' is not among the defined enum values. "
   1613                 "Enum name: %s. Possible values: %s"

LookupError: 'reed' is not among the defined enum values. Enum name: color. Possible values: red, green, blue
Broken again.

So how do we fix this?

Handling Unknown Values
All the cases we've seen of LookupErrors are essentially a problem that we have no unknown value handler - ultimately in all applications where the value could change - which I would argue should always be considered to be all of them - we in fact should have had an option which specified handling an unknown one.

At this point we need to subclass the SQLAlchemy Enum type, and specify that directly - which do like so:

import typing as t

class EnumWithUnknown(sqlalchemy.Enum):
    def __init__(self, *enums, **kw: t.Any):
        super().__init__(*enums, **kw)
        # SQLAlchemy sets the _adapted_from keyword argument sometimes, which contains a reference to the original type - but won't include
        # original keyword arguments, so we need to handle that here.
        self._unknown_value = kw["_adapted_from"]._unknown_value if "_adapted_from" in kw else kw.get("unknown_value",None)
        if self._unknown_value is None:
            raise ValueError("unknown_value should be a member of the enum")
    
    # This is the function which resolves the object for the DB value
    def _object_value_for_elem(self, elem):
        try:
            return self._object_lookup[elem]
        except LookupError:
            return self._unknown_value
And then we can use this type like follows:

class Color(Enum):
    UNKNOWN = "unknown"
    LEGACY_RED = "red"
    GREEN = "green"
    BLUE = "blue"

class Base(DeclarativeBase):
    pass

class TestTable(Base):
    __tablename__ = "test_table"
    id: Mapped[int] = mapped_column(primary_key=True)
    value: Mapped[Color] = mapped_column(EnumWithUnknown(Color, values_callable=lambda t: [ str(item.value) for item in t ], 
                                                         unknown_value=Color.UNKNOWN))
    
Let's run that against the database we just inserted reed into:

# Now try and read the values back
with Session(engine) as session:
    records = session.scalars(select(TestTable)).all()
    print("We restored the following values in code...")
    for record in records:
        print(record.value)
We restored the following values in code...
Color.LEGACY_RED
Color.GREEN
Color.BLUE
Color.UNKNOWN
And fixed! We obviously have changed our application logic, but this is now much safer and code which will work as we expect it too in all circumstances.

From a practical perspective we've had to expand our design space to assume indeterminate colors can exist - which might be awkward, but the trade-off is robustness: our application logic can now choose how it handles "unknown" - we could crash if we wanted, but we can also choose just to ignore those records we don't understand or display them as "unknown" and prevent user interaction or whatever else we want.

Discussion
This is an interesting case where in my opinion the "default" design isn't what you would want, but the logic for it is actually sound. SQLAlchemy models define databases - they are principally built on assuming you are describing the actual state of a database, with constraints provided by a database - i.e. in a database with first-class enumeration support, some of the tripwires here just wouldn't work without a schema upgrade.

Conversely, if you did a schema upgrade, your old applications still wouldn't know how to parse new values unless you did everything perfectly in lockstep - which in my experience isn't reality.

Basically it's an interesting case where everything is justifiably right, but leaves some design footguns lying around which might be a bit of a surprise (hence this post). The kicker for me is the effect on using session.scalar calls to return models - since unless we're querying more specifically, having unknown values we can't handle in tables leads to being unable to list any elements on the table ergonomically.

Conclusions
Think carefully before using automagic enum methods in SQLAlchemy. What you want to do now is likely subtly wrong, and while there's a simple and elegant way to use enum.Enum with SQLAlchemy, the magic will give you working code quickly but with potentially nasty problems from subtle bugs or data mismatches later.

Listings
The full listing for the code samples here can also be found here.

sqlalchemy-enums.py (Source)
#!/usr/bin/env python
# sqlalchemy-enums.py
# Note: you need to at least install `pip install sqlalchemy` for this to work.

from enum import Enum

import sqlalchemy
from sqlalchemy.orm import Mapped, DeclarativeBase, Session, mapped_column
from sqlalchemy import create_engine, select, text

import typing as t


class EnumWithUnknown(sqlalchemy.Enum):
    def __init__(self, *enums, **kw: t.Any):
        super().__init__(*enums, **kw)
        # SQLAlchemy sets the _adapted_from keyword argument sometimes, which contains a reference to the original type - but won't include
        # original keyword arguments, so we need to handle that here.
        self._unknown_value = (
            kw["_adapted_from"]._unknown_value
            if "_adapted_from" in kw
            else kw.get("unknown_value", None)
        )
        if self._unknown_value is None:
            raise ValueError("unknown_value should be a member of the enum")

    # This is the function which resolves the object for the DB value
    def _object_value_for_elem(self, elem):
        try:
            return self._object_lookup[elem]
        except LookupError:
            return self._unknown_value


class Color(Enum):
    UNKNOWN = "unknown"
    LEGACY_RED = "red"
    GREEN = "green"
    BLUE = "blue"


class Base(DeclarativeBase):
    pass


class TestTable(Base):
    __tablename__ = "test_table"
    id: Mapped[int] = mapped_column(primary_key=True)
    value: Mapped[Color] = mapped_column(
        EnumWithUnknown(
            Color,
            values_callable=lambda t: [str(item.value) for item in t],
            unknown_value=Color.UNKNOWN,
        )
    )


engine = create_engine("sqlite://")

Base.metadata.create_all(engine)

with Session(engine) as session:
    # Create normal values
    for enum_item in [Color.LEGACY_RED, Color.GREEN, Color.BLUE]:
        session.add(TestTable(value=enum_item))
    session.commit()

with Session(engine) as session:
    session.add(TestTable(value="reed"))
    session.commit()

# Now try and read the values back
with Session(engine) as session:
    records = session.scalars(select(TestTable)).all()
    print("We restored the following values in code...")
    for record in records:
        print(record.value)

print("But the underlying table contains...")
with engine.connect() as conn:
    print(conn.execute(text("SELECT * FROM test_table;")).all())

