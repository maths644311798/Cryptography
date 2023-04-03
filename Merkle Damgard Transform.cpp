/*
The Merkle-Damgard Transform.
  Let(Gen_h; h) be a fixed-length hash function with input length 2l(n) and
  output length l(n).Construct a variable-length hash function(Gen; H)
 */
#include <cmath>
#include <iostream>
#include<bitset>
#include<vector>
#include<string>
using namespace std;

typedef bitset<8> byte;

struct Message
{
    //assume the number of bits of a message is a multiple of 8
    unsigned long long len; //has len bits
    string m;

    Message(const unsigned long long& out_len, const string& out_m):
        len(out_len), m(out_m){}

    //convert a number to string, out_len is long enough to store L
    Message(const unsigned long long& out_len, unsigned long long L):
        len(out_len), m(out_len/8, 0)
    {
        unsigned int i = 0, rest_i = 0;
        while (L > 0)
        {
            rest_i = i % 8;
            if (L % 2 == 1)
            {
                m[i / 8] = m[i / 8] | (1 << rest_i);
            }
            L = L >> 1;
            ++i;
        }
    }

    void extend_to_multiple_of_8()
    {
        //extend x
        unsigned long long rest_bit = len - len / 8 * 8;
        if (rest_bit > 0)
        {
            m[len / 8] = m[len / 8] & ((1 << rest_bit) - 1);
            len = len + 8 - rest_bit;
        }
    }
};

Message concatenation(Message const & a, Message const & b)
{
    Message z(a.len + b.len, a.m + b.m);
    return z;
}

class Key
{
private:
    static const unsigned int n = 512; //security parameter
    static const unsigned int key_length = 1024;
public:
    typedef byte key_class[key_length / 8];
    key_class key;

    Key(Key* other)
    {
        for (int i = 0; i < key_length / 8; ++i)
        {
            key[i] = (other->key)[i];
        }
    }

    Key& operator=(const Key& other)
    {
        for (int i = 0; i < key_length / 8; ++i)
        {
            key[i] = (other.key)[i];
        }
    }
};

class Merkle_Damgard_Transform
{
private:
    static const unsigned int n = 512; //security parameter
    static const unsigned int key_length = 1024;

public:
    typedef byte key_class[key_length / 8];
    unsigned long long (*l)(unsigned int);
    Key(*Gen_h)(unsigned int);
    Message(*h)(Key, Message);

    Merkle_Damgard_Transform(Key (*Out_Gen_h)(unsigned int), Message(*Out_h)(Key, Message))
    {
        Gen_h = Out_Gen_h;
        h = Out_h;
    }

    Key Gen(unsigned int n)
    {
        return Gen_h(n);
    }

    Message H(const Key key, Message x)
    {
        x.extend_to_multiple_of_8();
        //hash
        const unsigned long long L = x.len;
        const unsigned long long ln = l(n);
        const unsigned long long B = L / ln;
        //assume l, L are multiples of 8
        string IV(ln / 8, 0);
        Message z(ln, IV);
        for (int i = 1; i <= B; ++i)
        {
            Message xi(l(n), x.m.substr((i - 1) * ln / 8, ln / 8));
            z = h(key, concatenation(z, xi));
        }
        Message message_L(l(n), L);
        return h(key, concatenation(z, message_L));
    }
};

int main()
{
    
    return 0;
}
