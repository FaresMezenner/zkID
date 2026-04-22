# Privacy-Preserving Age Verification

This project aims to build Privacy-Preserving Age Verification using privacy preserving techniques and algorithms, trying to match as much as possible the requirements as explained in the [attached document](./project-private-auth.pdf)

## Iteration 1

In this iteration we will focus on building the ID with one feature of the many mentioned features in mind: how can the prover prove that their above the threshold age without revealing any unwanted information?
First let's define our actors:

- **Issuer**: which could be the government or any actor that we trust in our protocol and is actually the actor who creates the ID.
- **Prover**: the ID holder who needs to prove the different statements.
- **Verifier**: the actor who needs to verify statements using the prover's ID, he could be someone gating the rollercoaster in the playground for example.

Let's keep our protocol simple in this iteration and directly hits the point:

- The issuer creates the ID using the values: birthday.
- The resulted ID is a set of pederson commitements to the different values, and the issuer signature to all these commitments using a standard symetrical encryption scheme.
- When a verifier wants to verify the age threshold, they verify that: the ID is issued by the trusted issuer using the signature, and the age of the ID holder is above the required threshold.

### Age Verification

The issuer creates the ID using the timestamp of the prover's birthday, this representation will make it easier for threshold verification since it is a single numerical value. to check that the birthday is valid, we need to calculate: $v_{age} = age\_timestamp + ((2^n)-1) - (current\_timestamp - birthday\_timestamp)$. Now if this value fits in $n$ bits then the threshold is verified. so the protocol will be as follows:

- The issuer provides a set of global elliptic curve points that we will use in the protocol, this includes $B$ and $G$.
- Since the issuer knows all the needed values, it generates the commitment using the birthday timestamp ($birthday$): $V_{birthday} = birthday\_timestamp.G + \gamma.B$, and it issues a signed ID that contains the commited value $V_{birthday}$. And sends $\gamma$ with the signed ID to the prover
- The verifier wants to verify that the prover age is above age threshold timestamp ($age\_timestamp$), so the prover prepares all the needed valeus
- The prover calculates $A_{age} =  <[age\_timestamp + ((2^n)-1) - (current\_timestamp - birthday\_timestamp)]_{2}, [G]> +  <[age\_timestamp + ((2^n)-1) - (current\_timestamp - birthday\_timestamp)]_{2} - [1]^n, [H]> + \alpha.B$, hence $A_{age} = <a_{L}, [G]> + <a_{R}, [H]> + \alpha.B$ where $a_{L} = [age\_timestamp (+ 2^n -1)- (current\_timestamp - birthday\_timestamp)]_{2}$ and $a_{R} = [age\_timestamp (+ 2^n -1)- (current\_timestamp - birthday\_timestamp)]_{2} - [1]^n = a_{L} - [1]^n$.
- The prover calculates and all the needed values upfront for threshold verification using fiat-shamir based bulletproof, Except for $V_{age}$. And sends everything to the verifier.
- The verifier calculates $V_{age} = V_{birthday} + (age\_timestamp + ((2^n)-1) - current\_timestamp).G $.
- The verifier verifies the signature ID, and verifies the age threshold proof.

So far our protocol is doing the minimum, but it has no expiry, it is traceable by the verifier, and it can't be revoked. We will work on each one in future iterations.
