// approximate

#include <cstdlib>
#include <cstring>

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
