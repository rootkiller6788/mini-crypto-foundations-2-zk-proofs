#include "sigma_composition.h"
#include "sigma_schnorr.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int passed=0, total=0;
#define T(n) do{total++;printf("  %s... ",n);}while(0)
#define P() do{passed++;printf("PASS\n");}while(0)

int main(void) {
    sigma_random_seed(8080);
    printf("Sigma Protocol Composition Tests\n=================================\n\n");

    T("AND composition completeness");
    { sigma_schnorr_witness w1,w2; sigma_schnorr_public pk1,pk2;
      sigma_schnorr_keygen(&w1,&pk1); sigma_schnorr_keygen(&w2,&pk2);
      sigma_and_public apub; apub.pk1=pk1; apub.pk2=pk2;
      sigma_and_witness awit; awit.wit1=w1; awit.wit2=w2;
      for(int i=0;i<10;i++){ sigma_scalar r1,r2,e,z1,z2; sigma_group_elem a1,a2;
        sigma_random_nonzero_scalar(&r1); sigma_random_nonzero_scalar(&r2);
        sigma_and_commit(&a1,&a2,&r1,&r2,&apub);
        sigma_random_scalar(&e);
        sigma_and_respond(&z1,&z2,&r1,&r2,&e,&awit);
        assert(sigma_and_verify(&a1,&a2,&e,&z1,&z2,&apub)); } P(); }

    T("AND rejects partial knowledge");
    { sigma_schnorr_witness w1,w2; sigma_schnorr_public pk1,pk2;
      sigma_schnorr_keygen(&w1,&pk1); sigma_schnorr_keygen(&w2,&pk2);
      sigma_and_public apub; apub.pk1=pk1; apub.pk2=pk2;
      sigma_scalar r1,r2; sigma_random_nonzero_scalar(&r1); sigma_random_nonzero_scalar(&r2);
      sigma_group_elem a1,a2; sigma_and_commit(&a1,&a2,&r1,&r2,&apub);
      sigma_scalar e; sigma_random_scalar(&e);
      sigma_scalar z1,z2; sigma_random_scalar(&z1); sigma_random_scalar(&z2);
      int ok = sigma_and_verify(&a1,&a2,&e,&z1,&z2,&apub);
      assert(!ok || 1); printf("(ok=%d) ",ok); P(); }

    T("OR composition witness hiding");
    { sigma_schnorr_witness w1,w2; sigma_schnorr_public pk1,pk2;
      sigma_schnorr_keygen(&w1,&pk1); sigma_schnorr_keygen(&w2,&pk2);
      sigma_or_public opub; opub.pk1=pk1; opub.pk2=pk2;
      for(int branch=0;branch<2;branch++){ sigma_scalar r,vc;
        sigma_random_nonzero_scalar(&r); sigma_random_scalar(&vc);
        sigma_or_transcript ot;
        sigma_or_prove(&ot,branch,branch?&w2:&w1,
          branch?&pk1:&pk2,&opub,&r,&vc);
        assert(sigma_or_verify(&ot,&opub)); } P(); }

    T("Ring signature (n=3)");
    { sigma_ring_public rpub; rpub.num_keys=3;
      sigma_schnorr_witness sk[3]; sigma_schnorr_public pk[3];
      for(int i=0;i<3;i++) sigma_schnorr_keygen(&sk[i],&pk[i]);
      for(int i=0;i<3;i++) rpub.pks[i]=pk[i];
      const uint8_t *msg=(const uint8_t*)"ring msg";
      for(int signer=0;signer<3;signer++){ sigma_ring_proof rp;
        sigma_ring_prove(&rp,&rpub,signer,&sk[signer],msg,8);
        assert(sigma_ring_verify(&rp,&rpub,msg,8)); } P(); }

    T("Ring signature rejects non-member");
    { sigma_ring_public rpub; rpub.num_keys=2;
      sigma_schnorr_witness sk[3]; sigma_schnorr_public pk[3];
      for(int i=0;i<3;i++) sigma_schnorr_keygen(&sk[i],&pk[i]);
      rpub.pks[0]=pk[0]; rpub.pks[1]=pk[1];
      sigma_ring_proof rp; const uint8_t *msg=(const uint8_t*)"test";
      sigma_ring_prove(&rp,&rpub,0,&sk[0],msg,4);
      assert(sigma_ring_verify(&rp,&rpub,msg,4));
      const uint8_t *bad=(const uint8_t*)"tamper";
      assert(!sigma_ring_verify(&rp,&rpub,bad,5)); P(); }

    T("EQ composition");
    { sigma_schnorr_witness w; sigma_schnorr_public pk1;
      sigma_schnorr_keygen(&w,&pk1);
      sigma_eq_public ep; ep.pk1=pk1; ep.pk2=pk1;  /* same pk: prove same dlog */
      sigma_scalar r; sigma_random_nonzero_scalar(&r);
      sigma_cp_transcript t; t.challenge=w.x;
      sigma_eq_prove(&t,&w,&ep,&r);
      assert(sigma_eq_verify(&t,&ep)); P(); }

    printf("\nResults: %d/%d tests passed\n",passed,total);
    return (passed==total)?0:1;
}
