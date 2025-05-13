import copy

class MyClass:
    def method(self):
        print("Hello")

obj = MyClass()
method_copy = copy.deepcopy(obj.method)

print(method_copy is obj.method)  # True


func_copy = copy.deepcopy(obj.method.__func__)

class MyClass:
    def __init__(self):
        self.value = 10

    def method(self):
        return self.value

    def save_current_method(self):
        saved = self.method  # This captures the current bound method

        def wrapper():
            return saved()  # Uses the captured method

        return wrapper

obj = MyClass()
saved_func = obj.save_current_method()

obj.value = 20
print(saved_func())  # Still returns 20, because it's calling the method live

class MyClass:
    def __init__(self):
        self.value = 10

    def method(self):
        return self.value

    def save_snapshot(self):
        result = self.method()  # Capture the result now

        def wrapper():
            return result  # Always returns the captured value

        return wrapper

obj = MyClass()
snap = obj.save_snapshot()

obj.value = 99
print(snap())  # → 10

class MyClass:
    def __init__(self):
        self.value = 10

    def method(self):
        return self.value

    def save_function(self):
        func = self.method.__func__  # Unbound function
        instance = self

        def wrapper():
            return func(instance)  # Manually call with current self

        return wrapper

import types

class MyClass:
    def __init__(self):
        self.value = 10

    def method(self):
        return self.value

    def snapshot_method(self):
        # Capture the unbound function and the current instance
        func = self.method.__func__  # Unbound function
        bound_self = self  # Instance to keep behavior tied to current state

        # Make a new method bound to the same instance and logic
        return types.MethodType(func, bound_self)

obj = MyClass()
saved_method = obj.snapshot_method()

# Now change the original method
obj.method = lambda: 42

print(obj.method())        # → 42
print(saved_method())      # → 10, uses the original method logic & self

obj.method = saved_method
print(obj.method())  # → 10

from collections import namedtuple

Point = namedtuple('Point', ['x', 'y'])
p = Point(1, 2)

print(p.x)  # 1
print(p.y)  # 2

from dataclasses import dataclass

@dataclass
class Point:
    x: int
    y: int

p = Point(1, 2)
print(p.x)  # 1
p.y = 10    # Allowed: it's mutable

@dataclass(frozen=True)
class Point:
    x: int
    y: int

from types import SimpleNamespace

p = SimpleNamespace(x=1, y=2)
print(p.x)  # 1
p.y = 10    # mutable

class MyThing:
    def __init__(self, value):
        self.value = value

    def __or__(self, other):
        return MyThing(self.value + other.value)

    def __repr__(self):
        return f"MyThing({self.value})"

a = MyThing(10)
b = MyThing(5)
c = a | b

print(c)  # MyThing(15)

class MyThing:
    def __init__(self, value):
        self.value = value

    def __ror__(self, other):
        return MyThing(other + self.value)

    def __repr__(self):
        return f"MyThing({self.value})"

result = 5 | MyThing(3)  # MyThing(8)
print(result)

