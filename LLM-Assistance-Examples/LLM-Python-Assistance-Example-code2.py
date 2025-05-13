class MyBase:
    def do_something(self):
        raise NotImplementedError("You must implement this method")

# Create an instance
obj = MyBase()

# Dynamically assign a method
def new_do_something(self):
    print("Now it's implemented!")

# Reassign the method on the class
MyBase.do_something = new_do_something

# Now calling the method works
obj.do_something()  # Output: Now it's implemented!

import types
obj.do_something = types.MethodType(new_do_something, obj)

import sys

# Writing directly to stdout
sys.stdout.write("Hello, world!\n")

with open("output.txt", "w") as f:
    sys.stdout = f
    print("This will go into output.txt")
sys.stdout = sys.__stdout__  # Restore default stdout

from io import StringIO

buffer = StringIO()
sys.stdout = buffer
print("Captured output")
sys.stdout = sys.__stdout__

print("Buffer contained:", buffer.getvalue())

def after_hook(method):
    def wrapper(self, *args, **kwargs):
        result = method(self, *args, **kwargs)
        self.after_any_hook()  # call the hook
        return result
    return wrapper

class MyClass:
    def after_any_hook(self):
        print("Hook called!")

    @after_hook
    def method_a(self):
        print("Doing A")

    @after_hook
    def method_b(self):
        print("Doing B")

    def method_c(self):
        print("C doesn't trigger hook")

def wrap_methods(cls, methods, hook_name):
    for name in methods:
        original = getattr(cls, name)
        def make_wrapper(method):
            def wrapper(self, *args, **kwargs):
                result = method(self, *args, **kwargs)
                getattr(self, hook_name)()
                return result
            return wrapper
        setattr(cls, name, make_wrapper(original))

class MyClass:
    def after_any_hook(self):
        print(">> After hook")

    def method_a(self): print("A")
    def method_b(self): print("B")
    def method_c(self): print("C")

wrap_methods(MyClass, ["method_a", "method_b"], "after_any_hook")

class MyClass:
    def after_any_hook(self):
        print(">> Hook!")

    def method_a(self): print("A")
    def method_b(self): print("B")
    def method_c(self): print("C")

    def __getattribute__(self, name):
        attr = super().__getattribute__(name)
        hook_methods = {"method_a", "method_b"}
        if callable(attr) and name in hook_methods:
            def hooked(*args, **kwargs):
                result = attr(*args, **kwargs)
                self.after_any_hook()
                return result
            return hooked
        return attr

def update_operators(method):
    def wrapper(self: Pipeline, *args, **kwargs):
        method(self, *args, **kwargs)  # call the original method
        self.set_next_and_reset()      # then call this hook method
    return wrapper

class Pipeline:
    def set_next_and_reset(self):
        print("Updating operators...")

    @update_operators
    def add_stage(self, stage):
        print(f"Adding stage: {stage}")

pipeline = Pipeline()
pipeline.add_stage("Transform")
# Output:
# Adding stage: Transform
# Updating operators...

from functools import wraps

def update_operators(method):
    @wraps(method)
    def wrapper(self: Pipeline, *args, **kwargs):
        result = method(self, *args, **kwargs)
        self.set_next_and_reset()
        return result
    return wrapper

@decorator
def some_function(...):
    ...

def some_function(...):
    ...

some_function = decorator(some_function)

@update_operators
def add_stage(self, stage):
    ...

def add_stage(self, stage):
    ...

add_stage = update_operators(add_stage)

print(pipeline.add_stage.__name__)  # probably 'wrapper' unless you used @wraps

from typing import Self

class Pipeline:
    def add_stage(self, stage: str) -> Self:
        # ... do stuff ...
        return self

from typing import TypeVar, Type

T = TypeVar("T", bound="Pipeline")

class Pipeline:
    def add_stage(self: T, stage: str) -> T:
        return self

pipeline.add_stage("foo").add_stage("bar")

class MyClass:
    @staticmethod
    def greet(name: str) -> str:
        return f"Hello, {name}!"

MyClass.greet("Alice")  # works fine
obj = MyClass()
obj.greet("Bob")        # also works, but no 'self'

from typing import Tuple

def process_point(point: Tuple[int, int]) -> None:
    x, y = point  # unpacking
    print(f"x: {x}, y: {y}")

# ❌ Not valid syntax
def func((x, y): Tuple[int, int]): ...

point: Tuple[int, int] = (5, 10)
x, y = point  # okay; x and y will be inferred as int

def handle_point(pt: Tuple[int, int]) -> None:
    match pt:
        case (x, y):
            print(f"x = {x}, y = {y}")

from typing import Tuple

def get_coords() -> Tuple[float, float]:
    return 1.0, 2.0

x, y = get_coords()  # x and y are floats
