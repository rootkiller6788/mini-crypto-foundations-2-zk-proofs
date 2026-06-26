#include "sigma_chaum_pedersen.h"
#include <stdio.h>
#include <assert.h>

static int passed=0, total=0;
#define T(n) do{total++;printf("  %s... ",n);}while(0)
#define P() do{passed++;printf("PASS\n");}while(0)

int main(void) {
    sigma_random_seed(77);
    printf("Chaum-Pedersen DLEQ Tests\n==========================\n\n");

    T("CP setup consistency");
    { sigma_chaum_pedersen_public pub; sigma_chaum_pedersen_witness wit;
      sigma_cp_setup_seeded(&pub,&wit,100);
      sigma_group_elem chk1,chk2;
      sigma_group_exp(&chk1,&pub.g1,&wit.x);
      sigma_group_exp(&chk2,&pub.g2,&wit.x);
      assert(sigma_group_eq(&chk1,&pub.y1));
      assert(sigma_group_eq(&chk2,&pub.y2)); P(); }

    T("CP completeness");
    { sigma_chaum_pedersen_public pub; sigma_chaum_pedersen_witness wit;
      sigma_cp_setup_seeded(&pub,&wit,200);
      for(int i=0;i<10;i++){ sigma_scalar r,e,z; sigma_group_elem a1,a2;
        sigma_random_nonzero_scalar(&r); sigma_cp_commit(&a1,&a2,&r,&pub);
        sigma_random_scalar(&e); sigma_cp_respond(&z,&r,&e,&wit);
        assert(sigma_cp_verify(&a1,&a2,&e,&z,&pub)); } P(); }

    T("CP special soundness");
    { sigma_chaum_pedersen_public pub; sigma_chaum_pedersen_witness wit;
      sigma_cp_setup_seeded(&pub,&wit,300);
      sigma_scalar r; sigma_random_nonzero_scalar(&r);
      sigma_group_elem a1,a2; sigma_cp_commit(&a1,&a2,&r,&pub);
      sigma_cp_transcript t1,t2;
      sigma_group_copy(&t1.a1,&a1); sigma_group_copy(&t1.a2,&a2);
      sigma_group_copy(&t2.a1,&a1); sigma_group_copy(&t2.a2,&a2);
      sigma_random_scalar(&t1.challenge);
      do{sigma_random_scalar(&t2.challenge);}while(sigma_scalar_cmp(&t1.challenge,&t2.challenge)==0);
      sigma_cp_respond(&t1.response,&r,&t1.challenge,&wit);
      sigma_cp_respond(&t2.response,&r,&t2.challenge,&wit);
      sigma_chaum_pedersen_witness ex;
      assert(sigma_cp_extract(&ex,&t1,&t2,&pub));
      assert(sigma_scalar_cmp(&ex.x,&wit.x)==0); P(); }

    T("CP SHVZK simulation");
    { sigma_chaum_pedersen_public pub; sigma_chaum_pedersen_witness wit;
      sigma_cp_setup_seeded(&pub,&wit,400); int ok=0;
      for(int i=0;i<50;i++){ sigma_scalar e; sigma_random_scalar(&e);
        sigma_cp_transcript sim; sigma_cp_simulate(&sim,&e,&pub);
        if(sigma_cp_verify(&sim.a1,&sim.a2,&sim.challenge,&sim.response,&pub)) ok++; }
      assert(ok==50); P(); }

    T("CP soundness");
    { sigma_chaum_pedersen_public pub; sigma_chaum_pedersen_witness wit;
      sigma_cp_setup_seeded(&pub,&wit,500); int fa=0;
      for(int i=0;i<100;i++){ sigma_group_elem fa_a; sigma_scalar fa_e,fa_z;
        sigma_random_scalar(&fa_e); sigma_random_scalar(&fa_z); sigma_group_exp_g(&fa_a,&fa_z);
        if(sigma_cp_verify(&fa_a,&fa_a,&fa_e,&fa_z,&pub)) fa++; }
      printf("(fa=%d/100) ",fa); assert(fa<=5); P(); }

    printf("\nResults: %d/%d tests passed\n",passed,total);
    return (passed==total)?0:1;
}
