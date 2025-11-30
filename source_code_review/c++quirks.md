# C++ Quirks and Language Comparisons

## Header/Implementation Separation

### C++
We put declarations in .h so that every translation unit can see the class or function interface, and we put the bodies in .cpp to avoid duplicate definitions and minimize recompilation when implementation change
If you put definitions into the .h, this happens:

**Problem 1: Multiple Definition Errors**

If 10 .cpp files include the same header with a non-inline function body:
- Each .cpp compiles its own copy.
- The linker sees 10 duplicates.
- You get a linker error.

### C Anchor
C follows a similar pattern with `.h` and `.c` files:
- **Header files (.h)**: Contain function declarations, type definitions, and macros
- **Implementation files (.c)**: Contain function definitions
- Uses `extern` keyword for global variables declared in headers
- No namespaces or classes; uses prefixes for naming conventions
- No templates; uses macros or void pointers for generic code

```c
// example.h
extern int global_var;
void my_function(int x);

// example.c
#include "example.h"
int global_var = 42;
void my_function(int x) { /* implementation */ }
```

### Java Anchor
Java has no header files, everything is in one place:
- **Single .java file per public class**: Contains both interface and implementation
- **No linker errors from multiple definitions**: The JVM class loader handles uniqueness
- **Compilation units are classes**: Each .java file is compiled to a .class bytecode file
- **Import statements**: Reference other classes by name, not file inclusion
- **No separation needed**: Interface and implementation live together unless you explicitly use `interface` keyword

```java
// MyClass.java; everything in one file
public class MyClass {
    private int value;
    
    public void myMethod() {
        // implementation here
    }
}
```

### What this means:

In C++, you **must** separate:
```cpp
class MyClass {        // .h file: interface
    void method();
};

void MyClass::method() { }  // .cpp file: implementation
```

In Java, for a regular class, everything is together:
```java
public class MyClass {
    public void method() { }  // interface + implementation in one place
}
```

**BUT**, Java has an `interface` keyword for defining pure contracts:
```java
// This is a pure interface; no implementation allowed (pre-Java 8)
public interface MyInterface {
    void method();  // just the signature
    int calculate(int x);
}

// Implementation class
public class MyClass implements MyInterface {
    @Override
    public void method() {
        // now we provide the implementation
    }
    
    @Override
    public int calculate(int x) {
        return x * 2;
    }
}
```

### Comparison:

| Language | Separation Pattern |
|----------|-------------------|
| **C++** | Physical separation: .h (interface) and .cpp (implementation) are different files |
| **Java classes** | No separation: interface and implementation in same class body |
| **Java interfaces** | Logical separation: `interface` defines contract, implementing classes provide behavior |

**The key insight**: Java's `interface` keyword creates a *logical* separation (contract vs implementation) within the same file-per-class model, whereas C++ creates a *physical* separation (different files) for the same class.