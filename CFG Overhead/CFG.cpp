#include <iostream>
#include <chrono>

// Base class with a virtual function
class Base
{
public:
    virtual void func() = 0;
};

// Derived classes implementing func()
class Derived1 : public Base
{
    volatile int x = 0; // Prevent optimization
public:
    void func() override
    {
        x += 1;
    }
};

class Derived2 : public Base
{
    volatile int y = 0; // Prevent optimization
public:
    void func() override
    {
        y += 2;
    }
};

// Factory function to create objects (prevents devirtualization)
Base* createObject()
{
    volatile int choice = 0; // Volatile to prevent compile-time resolution
    return (choice != 0) ? (Base*)new Derived1() : (Base*)new Derived2();
}

int main()
{
    const int iterations = 1000000000; // Adjust based on system speed
    Base* obj = createObject();

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i)
    {
        obj->func(); // Indirect call stressed here
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "Time taken: " << duration << " ms" << std::endl;

    delete obj;
    return 0;
}