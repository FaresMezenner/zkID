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
- The resulted ID is a set of pederson commitements to the different values, and the issuer signature to all these commitments using a standard asymmetric digital signature.
- When a verifier wants to verify the age threshold, they verify that: the ID is issued by the trusted issuer using the signature, and the age of the ID holder is above the required threshold.

### Age Verification

The issuer creates the ID using the timestamp of the prover's birthday, this representation will make it easier for threshold verification since it is a single numerical value. to check that the birthday is valid, we need to calculate: $v_{age} = age\_timestamp + ((2^n)-1) - (current\_timestamp - birthday\_timestamp)$. Now if this value fits in $n$ bits then the threshold is verified. so the protocol will be as follows:

- The issuer provides a set of global elliptic curve points that we will use in the protocol, this includes $B$ and $G$. And also include $current_timestamp$ inm the global params.
- Since the issuer knows all the needed values, it generates the commitment using the birthday timestamp ($birthday$): $V_{birthday} = birthday\_timestamp.G + \gamma.B$, and it issues a signed ID that contains the commited value $V_{birthday}$. And sends $\gamma$ with the signed ID to the prover. You might ask why does the issuer includes $\gamma$ in the signature, it is because if we don't include it, the verifier will have access to $birthday\_timestamp.G$ which could be bruteforced easily.
- The verifier wants to verify that the prover age is above age threshold timestamp ($age\_timestamp$), so the prover prepares all the needed valeus
- The prover calculates $A_{age} =  <[age\_timestamp + ((2^n)-1) - (current\_timestamp - birthday\_timestamp)]_{2}, [G]> +  <[age\_timestamp + ((2^n)-1) - (current\_timestamp - birthday\_timestamp)]_{2} - [1]^n, [H]> + \alpha.B$, hence $A_{age} = <a_{L}, [G]> + <a_{R}, [H]> + \alpha.B$ where $a_{L} = [age\_timestamp (+ 2^n -1)- (current\_timestamp - birthday\_timestamp)]_{2}$ and $a_{R} = [age\_timestamp (+ 2^n -1)- (current\_timestamp - birthday\_timestamp)]_{2} - [1]^n = a_{L} - [1]^n$.
- The prover calculates and all the needed values upfront for threshold verification using fiat-shamir based bulletproof, Except for $V_{age}$. And sends everything to the verifier.
- The verifier calculates $V_{age} = V_{birthday} + (age\_timestamp + ((2^n)-1) - current\_timestamp).G $.
- The verifier verifies the signature ID, and verifies the age threshold proof.

So far our protocol is doing the minimum, but it has no expiry, it is traceable by the verifier, and it can't be revoked. We will work on each one in future iterations.

## Iteration 2

In this iteration we will get to the second basic feature, how to make the digital non traceable? currently, differents verifiers could collectively track an ID signatures and whit some social engineering they could trace it back to the user and extract any information they want.
To fix this, we need a signature scheme that allows us to prove that the ID is signed by the issuer but without the ability to track the ID, this is possible thanks to PS re-randomizable Signature scheme alongside Chaum-Pedersen proof of equality of discrete logarithms.
Currently, the issuer issues an ID with $V_{birthday} = birthday\_timestamp.G + \gamma.B$, and the signature $Signature = Enc(V_{birthday}, sk)$, and the verifiers verifies the signature by checking that $Dec(Signature, pk) = V_{birthday}$, as we see the signature is fixed across verifications, to fix this we will make the signature change in each different verification in the following way:

- The issuer generates its secret and public keys: $sk = (x,y) \in \mathbb{F}_{p}^2$ and $pk = (\tilde{X}, \tilde{Y}) = (x·G_{2}, y·G_{2})$

- Since the $V_{birthday}$ value will will be random each time the hodler interacts with the verifier, and based on our selected scheme, the issuer will sign the value $birthday\_timestamp$ directly by picking a random $h \in \mathbb{G}_1$, computing $(\sigma_{1}$,$\sigma_{2}) = (h, h^{x+y·birthday\_timestamp})$, and giving it to the holder.
- Now at each verification, the prover will provide to the verifier the values $V_{birthday} = birthday\_timestamp.G + \gamma.B$ and the signature $(\sigma_{1}',\sigma_{2}') = (t·\sigma_{1},t·\sigma_{2})$ where $t \in \mathbb{F}_{p}$ and $\gamma \in \mathbb{F}_{p}$ are randomly picked, and the verifier will need to verify the following two things:
  - The prover knows an oppening $(birthday\_timestamp, \gamma)$ to the commitment $V_{birthday}$.
  - The signature $(\sigma_{1}',\sigma_{2}')$ is a valid signature for the same value $birthday\_timestamp$.
- The above two could be verified thanks to the Chaum-Pedersen proof of equality of discrete logarithms.
- **Verifying the signature:**
  - Trivially, to verify the signature the prover provides $birthday\_timestamp$ to the verifier and checks the equation $e(\sigma_{2}', G_{2}) = e(\sigma_{1}', \tilde{X}·\tilde{Y}^{birthday\_timestamp}) \iff e(t·h^{x+y·birthday\_timestamp}, G_{2}) = e(t·h, x·G_{2} + y·birthday\_timestamp·G_{2}) \iff e(h, G_{2})^{t·(x+y·birthday\_timestamp)} = e(h,G_{2})^{t·(x+y·birthday\_timestamp)}$, but we want to keep $birthday\_timestamp$ private, so we will make the verifier verifies the signature in ZK.
  - First let's make the problem clearer by isolating $birthday\_timestamp$ as follows: $e(\sigma_{2}', G_{2}) = e(\sigma_{1}', \tilde{X}·\tilde{Y}^{birthday\_timestamp}) \iff e(\sigma_{2}', G_{2}) = e(\sigma_{1}', \tilde{X})·e(\sigma_{1}', \tilde{Y}^{birthday\_timestamp}) \iff \frac{e(\sigma_{2}', G_{2})}{e(\sigma_{1}', \tilde{X})}=e(\sigma_{1}', \tilde{Y})^{birthday\_timestamp} \iff  Z = F^{birthday\_timestamp}$, hence the problem is s tandar Schnorr discrete log proof in $\mathbb{G}_{T}$ where the prover wants to prove that it knows a value $birthday\_timestamp$ that is the discrete log of $Z$ to the base $F$, which are publicly calculable values.
  - The prover picks a random $r_{v}$ and commits to it $A_{2} = F^{r_{v}} =e(\sigma_{1}', \tilde{Y})^{r_{v}}$
  - Using Fiat-Schamir the prover caculates the challenge non-interactively: $c = H(V_{birthday}, \sigma_{1}',\sigma_{2}', A_{1}, A_{2})$ (we will see what is $A_{1}$ when we get to the commitment opening verification)
  - The prover sends $s_{v} = r_{v} - c·birthday\_timestamp mod p$, which is giving $birthday\_timestamp$ but hidden behind $r_{v}$, here where the ZK property kicks in.
  - And the verifier will calculate $c$ on its own and check that $F^{s_{v}}·Z^{c} = A_{2} \iff F^{r_{v} - c·birthday\_timestamp}·F^{birthday\_timestamp·c} = A_{2}$.
  - Once we substitute back the definitions of $Z$ and $F$ we get the formal signature verification formula:  $e(\sigma_{1}', \tilde{Y})^{s_{v}}·(\frac{e(\sigma_{2}', G_{2})}{e(\sigma_{1}', \tilde{X})})^{c} = A_{2}$.
- **Verifying that the prover has a valid opening to the pedersong commitment:**
  - This is a basic ZK-opening of a Pederson Commitment using a sigma protocol, with some caveats:
  - The prover generates a new value $r_{\gamma} \in \mathbb{F}_{p}$ alongside the one we already generated $r_{v}$, we use the same $r_{v}$ to enforce the fact that the value $birthday\_timestamp$ we have the signature of $(\sigma_{1}',\sigma_{2}')$ is the same one we are using to open the commitment. And then we commit to them $A_{1} = r_{v}·G + r_{\gamma}·B$
  - Using the same challenge, the prover generates $s_{\gamma} = r_{gamma} - c·\gamma mod p$, and sends $(s_{v}, s_{\gamma})$ to the verifier.
  - The verifier, using the same calculated challenge $c$, verifies $s_{v}·G + s_{\gamma}·B + c·V_{birthday} = A_{1}$

And like this, sence in each verification the prover sends a new blinded values $(\sigma_{1}',\sigma_{2}')$ and $V_{birthday}$, the traceability is impossible even if the verifier and issuer colluded
