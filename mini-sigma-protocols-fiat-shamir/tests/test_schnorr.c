#include "sigma_schnorr.h"
#include "sigma_core.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int passed = 0, total = 0;
#define T(n) do { total++; printf("  %s... ", n); } while(0)
#define P()   do { passed++; printf("PASS\n"); } while(0)
#define F(m)  do { printf("FAIL: %s\n", m); } while(0)

int main(void) {
    sigma_random_seed(42);
    printf("Schnorr Sigma Protocol Tests\n============================\n\n");

    T("keygen consistency");
    { sigma_schnorr_witness sk; sigma_schnorr_public pk;
      sigma_schnorr_keygen(&sk, &pk);
      sigma_group_elem chk; sigma_group_exp_g(&chk, &sk.x);
      assert(sigma_group_eq(&chk, &pk.y)); P(); }

    T("completeness (10 rounds)");
    { sigma_schnorr_witness sk; sigma_schnorr_public pk;
      sigma_schnorr_keygen(&sk, &pk);
      for(int i=0;i<10;i++){ sigma_scalar r,e,z; sigma_group_elem a;
        sigma_random_nonzero_scalar(&r); sigma_schnorr_commit(&a,&r);
        sigma_random_scalar(&e); sigma_schnorr_respond(&z,&r,&e,&sk.x);
        assert(sigma_schnorr_verify(&a,&e,&z,&pk.y)); } P(); }

    T("special soundness");
    { sigma_schnorr_witness sk; sigma_schnorr_public pk;
      sigma_schnorr_keygen(&sk, &pk);
      sigma_scalar r; sigma_random_nonzero_scalar(&r);
      sigma_group_elem a; sigma_schnorr_commit(&a,&r);
      sigma_transcript t1,t2; sigma_group_copy(&t1.commitment,&a); sigma_group_copy(&t2.commitment,&a);
      sigma_random_scalar(&t1.challenge);
      do{sigma_random_scalar(&t2.challenge);}while(sigma_scalar_cmp(&t1.challenge,&t2.challenge)==0);
      sigma_schnorr_respond(&t1.response,&r,&t1.challenge,&sk.x);
      sigma_schnorr_respond(&t2.response,&r,&t2.challenge,&sk.x);
      sigma_scalar ex; assert(sigma_schnorr_extract(&ex,&t1,&t2,&pk.y));
      assert(sigma_scalar_cmp(&ex,&sk.x)==0); P(); }

    T("SHVZK simulation");
    { sigma_schnorr_witness sk; sigma_schnorr_public pk;
      sigma_schnorr_keygen(&sk, &pk); int ok=0;
      for(int i=0;i<50;i++){ sigma_scalar e; sigma_random_scalar(&e);
        sigma_transcript sim; sigma_schnorr_simulate(&sim,&e,&pk.y);
        if(sigma_schnorr_verify(&sim.commitment,&sim.challenge,&sim.response,&pk.y)) ok++; }
      assert(ok==50); P(); }

    T("soundness (false proofs)");
    { sigma_schnorr_witness sk; sigma_schnorr_public pk;
      sigma_schnorr_keygen(&sk,&pk); int fa=0;
      for(int i=0;i<100;i++){ sigma_group_elem fa_a; sigma_scalar fa_e,fa_z;
        sigma_random_scalar(&fa_e); sigma_random_scalar(&fa_z); sigma_group_exp_g(&fa_a,&fa_z);
        if(sigma_schnorr_verify(&fa_a,&fa_e,&fa_z,&pk.y)) fa++; }
      printf("(fa=%d/100) ",fa); assert(fa<=5); P(); }

    T("deterministic keygen");
    { sigma_schnorr_witness sk1,sk2; sigma_schnorr_public pk1,pk2;
      sigma_schnorr_keygen_seeded(&sk1,&pk1,12345);
      sigma_schnorr_keygen_seeded(&sk2,&pk2,12345);
      assert(sigma_scalar_cmp(&sk1.x,&sk2.x)==0);
      assert(sigma_group_eq(&pk1.y,&pk2.y)); P(); }

    T("knowledge error bound");
    { sigma_schnorr_witness sk; sigma_schnorr_public pk;
      sigma_schnorr_keygen(&sk,&pk);
      const sigma_protocol *p = sigma_schnorr_get_protocol();
      double ke = sigma_estimate_knowledge_error(p,&pk,200);
      printf("(kappa=%.3f) ",ke); assert(ke<0.1); P(); }

    T("HVZK acceptance rate");
    { sigma_schnorr_witness sk; sigma_schnorr_public pk;
      sigma_schnorr_keygen(&sk,&pk);
      const sigma_protocol *p = sigma_schnorr_get_protocol();
      double r = sigma_check_hvzk(p,&pk,100);
      printf("(rate=%.2f) ",r); assert(r>=0.95); P(); }

    printf("\nResults: %d/%d tests passed\n",passed,total);
    return (passed==total)?0:1;
}
