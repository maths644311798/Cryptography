
#include "lweSecretKey.h"
#include "lweCipherText.h"


class lweDecryptor {
private:
	lweSecretKey sk_;
	seal::SEALContext context_;
    
public:
	lweDecryptor(const seal::SEALContext& context, const lweSecretKey& sk)
		: sk_(sk), context_(context){
            // Seal's copy constructor is enough
        };

/*Only allow one modulus in q*/
	uint64_t Decrypt(const LWECT& ct);
};
