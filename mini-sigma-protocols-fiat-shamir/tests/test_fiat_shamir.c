#include "sigma_fiat_shamir.h"
#include "sigma_schnorr.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int passed=0, total=0;
#define T(n) do{total++;printf("  %s... ",n);}while(0)
#define P() do{passed++;printf("PASS\n");}while(0)

int main(void) {
    sigma_random_seed(2024);
    printf("Fiat-Shamir Transform Tests\n============================\n\n");

    T("FS proof generation and verification");
    { sigma_schnorr_witness sk; sigma_schnorr_public pk;
      sigma_schnorr_keygen(&sk,&pk);
      const uint8_t *msg=(const uint8_t*)"test message"; size_t mlen=12;
      sigma_scalar r; sigma_random_nonzero_scalar(&r);
      sigma_proof proof; sigma_fs_schnorr_prove(&proof,&sk,&pk,msg,mlen,&r);
      assert(sigma_fs_schnorr_verify(&proof,&pk,msg,mlen)); P(); }

    T("FS signature sign and verify");
    { sigma_schnorr_witness sk; sigma_schnorr_public pk;
      sigma_schnorr_keygen(&sk,&pk);
      const uint8_t *msg=(const uint8_t*)"sign this message"; size_t mlen=18;
      sigma_fs_signature sig;
      sigma_fs_sign(&sig,&sk,&pk,msg,mlen);
      assert(sigma_fs_verify_signature(&sig,&pk,msg,mlen)); P(); }

    T("FS signature rejects tampered message");
    { sigma_schnorr_witness sk; sigma_schnorr_public pk;
      sigma_schnorr_keygen(&sk,&pk);
      const uint8_t *msg=(const uint8_t*)"original"; size_t mlen=8;
      sigma_fs_signature sig; sigma_fs_sign(&sig,&sk,&pk,msg,mlen);
      const uint8_t *bad=(const uint8_t*)"tampered"; size_t blen=8;
      assert(!sigma_fs_verify_signature(&sig,&pk,bad,blen)); P(); }

    T("FS signature rejects wrong public key");
    { sigma_schnorr_witness sk1,sk2; sigma_schnorr_public pk1,pk2;
      sigma_schnorr_keygen(&sk1,&pk1); sigma_schnorr_keygen(&sk2,&pk2);
      const uint8_t *msg=(const uint8_t*)"msg"; size_t mlen=3;
      sigma_fs_signature sig; sigma_fs_sign(&sig,&sk1,&pk1,msg,mlen);
      assert(!sigma_fs_verify_signature(&sig,&pk2,msg,mlen)); P(); }

    T("FS strong Fiat-Shamir check");
    { assert(sigma_fs_is_strong()); P(); }

    T("FS serialization roundtrip");
    { sigma_schnorr_witness sk; sigma_schnorr_public pk;
      sigma_schnorr_keygen(&sk,&pk);
      const uint8_t *msg=(const uint8_t*)"serialize me";
      sigma_fs_signature sig; sigma_fs_sign(&sig,&sk,&pk,msg,13);
      uint8_t buf[512]; sigma_fs_signature_serialize(buf,&sig);
      sigma_fs_signature sig2;
      assert(sigma_fs_signature_deserialize(&sig2,buf));
      assert(sigma_fs_verify_signature(&sig2,&pk,msg,13)); P(); }

    T("FS forgery resistance");
    { double rate = sigma_fs_test_forgery_resistance(500);
      printf("(forgery_rate=%.4f) ",rate);
      assert(rate < 0.05); P(); }

    T("FS batch verification (n=3)");
    { sigma_schnorr_witness sk; sigma_schnorr_public pk;
      sigma_schnorr_keygen(&sk,&pk);
      sigma_fs_signature sigs[3]; sigma_schnorr_public pks[3];
      const uint8_t *msgs[3]; size_t lens[3];
      const uint8_t *m0=(const uint8_t*)"msg0",*m1=(const uint8_t*)"msg1",*m2=(const uint8_t*)"msg2";
      sigma_fs_sign(&sigs[0],&sk,&pk,m0,4); sigma_fs_sign(&sigs[1],&sk,&pk,m1,4); sigma_fs_sign(&sigs[2],&sk,&pk,m2,4);
      pks[0]=pk; pks[1]=pk; pks[2]=pk;
      msgs[0]=m0; msgs[1]=m1; msgs[2]=m2; lens[0]=4; lens[1]=4; lens[2]=4;
      assert(sigma_fs_batch_verify(sigs,pks,msgs,lens,3)); P(); }

    printf("\nResults: %d/%d tests passed\n",passed,total);
    return (passed==total)?0:1;
}
