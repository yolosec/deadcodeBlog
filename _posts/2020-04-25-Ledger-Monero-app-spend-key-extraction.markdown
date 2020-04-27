---
layout: post
title:  "CVE-2020-6861: Ledger Monero App Spend key Extraction"
date:   2020-04-25 08:00:00 +0100
categories: blog
tags: ledger monero app spend key extraction bug protocol poc
excerpt_separator: <!-- more -->

---

CVE-2020-6861: Due to a bug in the Monero transaction signing protocol in the Ledger Monero app 
we were able to extract master Monero spending key. 

<!-- more -->

<p style="text-align: center;">
    <a href="https://twitter.com/Ledger/status/1068127566752608256?s=20">
        {% imagesize /static/monero/monero.jpeg:img/3 alt='Monero + Ledger' %}
    </a>
</p>

## Intro

[Monero] is a privacy-centric cryptocurrency protecting the identity of participants and amounts being transacted.
Monero support has been added to [Ledger], cryptocurrency hardware wallet, in [November 2018][monero-ledger-support].  

<video controls="" width="660" height="465" autoplay="" muted="" loop="">
    <source src="/static/monero/monero.mp4" type="video/mp4" />
    Sorry, your browser doesn't support embedded videos.
</video>

<!--
<p>
<iframe width="660" height="465" src="https://www.youtube.com/embed/50VczNVR7l8?rel=0" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
</p>
-->

### Monero basics - points and scalars

[Zero to Monero] is an excellent resource describing cryptography used in Monero from scratch. 
I recommend going through it if something is not clear in this post.

Monero is based on an elliptic curve [Ed25519]. 
Public keys are points on the Ed25519 curve \\(\mathbb{G}\\), denoted as upper-case letters. 
Point \\(G\\) is a known parameter called the *base point*. Points form a finite [cyclic group](https://en.wikipedia.org/wiki/Cyclic_group), 
so operations of addition and subtraction are defined over points. Operation over two
points results in another point on the curve. Points are encoded to 32 bytes.
 
Scalars are integers modulo \\(l\\), i.e. \\(\mathbb{Z}^{\*}\_{l} \\), where \\(l = 2^{252}\\)+27742317777372353535851937790883648493 is a curve order (number of points on the elliptic curve). 
Scalars are denoted as lower-case letters. As \\(l\\) is a prime number, \\(\mathbb{Z}^{\*}\_{l}\\) is a [finite field](https://en.wikipedia.org/wiki/Finite_field), i.e., there are addition, subtraction, multiplication and division operations defined over the scalars. 

Moreover, we have an operation called *scalar multiplication*, \\(bP = \overbrace{(P + P + \cdots + P)}^{b} = Q\\), where \\(b \in \mathbb{Z}^{\*}\_{l}, P \in \mathbb{G}, Q \in \mathbb{G}\\). 
Scalars also work as private keys, by computing \\(bG=B\\) we get public key \\(B\\).
Scalar multiplication in non-invertible, i.e., computation of \\(b\\) from \\(B\\) is not feasible (reduces to solving [discrete logarithm problem](https://en.wikipedia.org/wiki/Discrete_logarithm)). Scalars are encoded as 32 bytes.

### Monero private keys

Monero wallet has a pair of private keys \\((k^s, k^v)\\) called spending and view key. Spending key is essential for spending owned Monero coins while view key is needed to determine whether transaction on the blockchain is for our account. Monero address contains public spend and view key, \\((k^sG, k^vG) = (K^s, K^v)\\).

Private keys \\((k^s, k^v)\\) are protected by hardware wallets in a way they never leave the device and
enables the user to use them only in a predefined way, i.e., the user has to confirm destination address and amount to be transacted before the hardware wallet uses keys to sign the transaction. 

However, the view key \\(k^v\\) is often exported from the hardware wallet and stored in the software wallet as it is needed for common read-only Monero operations. The software wallet with the view key can scan incoming transactions, determine whether we received any funds, and decode the value of those funds. This can be done without having the hardware wallet connected. Without exporting the view key, the hardware wallet would have to be connected, and cryptographic operations would have to be computed over each transaction in each block, which would be quite slow. 

The view key is derived from the spend key. Thus the spend key \\(k^s\\) is the main secret we aim to extract from the hardware wallet. Once extracted, the wallet is compromised, the attacker can transact all funds, which is game over.

## Transaction signing

Signing a Monero transaction is more complicated than a Bitcoin transaction, for example. 
As hardware wallets (HWs) are resource-limited hardware, they cannot sign the whole transaction at once, and thus some transaction signing protocol has to be used to sign the transaction in a secure way, i.e., without leaking any secrets signing precisely what user confirms. 

Ledger application implementing such Monero signing algorithm is [https://github.com/LedgerHQ/ledger-app-monero](https://github.com/LedgerHQ/ledger-app-monero). Documentation of the commands provided by the Monero application is [here](https://github.com/LedgerHQ/ledger-app-monero/blob/master/doc/developer/blue-app-commands.pdf).

The Monero wallet then calls given commands in order to sign the transaction. 
Ledger's transaction signing protocol runs low-level, i.e., operations provided by the HW app are usually simple commands. The operation's input and outputs are protected by AES128-CBC (zero IV) and HMAC. 
Encryption key `spk` is derived from the spend key and remains the same for the whole life of the wallet. HMAC key `hk` is random, generated for each transaction. I denote scalars and points as *sealed* if they are encrypted and HMAC protected, i.e., not readable by the attacker. 

### Decryption oracle

The app is implemented in C, but I will show the core ideas in python for brevity.
Take a look at the [`sc_sub`](https://github.com/ph4r05/blue-app-monero/blob/7d6c5f5573c4c83fe74dcbb3fe6591489bae7828/src/monero_key.c#L430) operation that shows how input and outputs are handled:

```python
def sc_sub(a: SealedScalar, b: SealedScalar) -> SealedScalar:
    """Input: {a, b} scalars"""
    aa = hmac_and_decrypt(a, spk, hk)
    bb = hmac_and_decrypt(b, spk, hk)
    cc = (aa - bb) % l  # l is the curve order
    c = encrypt_and_hmac(cc, spk, hk)
    return c
```

There are few others operations provided by the HW app. Scalars either as inputs or function outputs are always encrypted, with one exception, function [`mlsag_sign`](https://github.com/ph4r05/blue-app-monero/blob/7d6c5f5573c4c83fe74dcbb3fe6591489bae7828/src/monero_mlsag.c#L96):

```python
def mlsag_sign(alpha: SealedScalar, x: SealedScalar) -> Scalar:
    aa = hmac_and_decrypt(alpha, spk, hk)  
    xx = hmac_and_decrypt(x, spk, hk)
    ss = (aa - c * xx) % l  # c is part of the state
    return ss
```

Resulting scalars `ss` are public part of the MLSAG signature in the transaction; thus the output of `mlsag_sign` is not encrypted. Scalar `c` is part of the internal state, which we know (not important now). 

Note that if we pass `x=0` to the `mlsag_sign`, we obtain *decrypting oracle* as the function returns a decrypted scalar value of the `alpha`. For that, we need an encrypted version of a zero scalar, which we can obtain by calling `zero = sc_sub(x, x)` for any encrypted scalar value `x`. We can thus decrypt all private values sent over the protocol.

```python
def decrypt_oracle(x: SealedScalar) -> Scalar:
    zero = sc_sub(x, x)  # can be reused
    xx = mlsag_sign(alpha=xx, x=zero)
```

If we could just pass \\(k^s\\) (sometimes denoted also as `b`) to the `decrypt_oracle` we won. But there are a few more steps required.

### Spend key extraction

There are few operations that enable work with stored spend and view keys. If such operations find
32 B placeholders `C_FAKE_SEC_VIEW_KEY`, `C_FAKE_SEC_SPEND_KEY` in the input, the real values are substituted to the input buffer, so the operation works with the real values. The placeholders are known to the software wallet once transaction signing started, so the signing protocol can work with these secret values. Function taking care of the substitution is: [`monero_io_fetch_decrypt_key`](https://github.com/ph4r05/blue-app-monero/blob/7d6c5f5573c4c83fe74dcbb3fe6591489bae7828/src/monero_io.c#L258). The `mlsag_sign` operation does not support the placeholders, so we need to find another function suitable for the spend key extraction.

Observe the [`derive_secret_key`](https://github.com/ph4r05/blue-app-monero/blob/7d6c5f5573c4c83fe74dcbb3fe6591489bae7828/src/monero_key.c#L574):

```python
def derive_secret_key(
        derivation: SealedPoint, 
        index: int, 
        secret: SealedScalar
    ) -> SealedScalar:
    D = hmac_and_decrypt(derivation)
    s = monero_io_fetch_decrypt_key(secret)  # Placeholder
    r = Hs(D || varint(index)) + s   
    res = encrypt_and_hmac(r, spk, hk)
    return res
```

The function computes \\(r=\mathcal{H}\_s(D \; \|\| \; \text{index}) + s\\), where \\(\mathcal{H}\_s: \\{0,1\\}^* \rightarrow \mathbb{Z}^{\*}\_{l} \\) is a hash function to scalars and `||` is a binary concatenation.

As you noticed, Monero app makes no difference between point and scalar encryption, thus we can use them interchangeably.
If we know the value of the \\(D\\) (one known value is the encryption of zero) we also known the value of \\(\mathcal{H}\_s(D \; \|\| \; \text{index})\\). Thus we can compute \\(s = r - \mathcal{H}\_s(D \; \|\| \; \text{index})\\).

Spend key extraction is thus:

```python
def poc1():
    C_FAKE_SEC_SPEND_KEY = monero_apdu_open_tx()
    x, X = generate_keypair()  # sealed scalar, clear point
    zero = sc_sub(x, x)
    r = derive_secret_key(zero, 0, C_FAKE_SEC_SPEND_KEY)
    rr = mlsag_sign(r, zero)
    b = r - H_s("\x00"*32 + "\x00")
    return b
```

The spend key `b` is extracted from the Monero app with just 5 API calls. No user interaction is needed. Ledger does not change any state or change the display, so the attack is unobservable by a normal user.  

The PoC demonstrating the vulnerability is [here](https://github.com/ph4r05/ledger-app-monero-1.42-vuln/blob/3e615bbfe4c4112ddc9e4099a1ba8378f37ab90b/poc.py#L114).

### Requirements

- Connected Ledger, entered PIN, selected Monero app 1.4.2. Commit 7d6c5f5573c4c83fe74dcbb3fe6591489bae7828. 
- Usually, when sending a transaction, setting up the Monero wallet.
- If the master view key was not exported, then the scenario happens with each blockchain scanning.

### Impact

- No user confirmation is required to mount the attack.
- The user is not notified about the transaction being in progress. No error is shown. The display does not change.
- The user has no chance to notice his master spend key was extracted.
- The exploitation was possible from the initial
protocol deployment date. User spend keys could have been silently exfiltrated without users knowing.
There is no way to tell whether this attack was executed in the wild. 
- Existing spend keys should thus be considered leaked and not secure to use.
- Ledger Monero app currently does not support changing the BIP-44 derivation path for 
Monero master key derivation, thus users are currently not able to use Ledger to store Monero securely
if they used it with the Monero before.

### Timeline

 -  _2. Jan 2020_: vulnerability discovery
 -  _3. Jan 2020_: vulnerability report sent
 -  _5. Jan 2020_: Response from Ledger, investigation started
 - _11. Jan 2020_: Response from Ledger acknowledging the vulnerability, working on fixes
 - _16. Jan 2020_: Interactive discussion started, refining countermeasures 
 -  _6. Feb 2020_: Final source code ready
 -  _2. Mar 2020_: Monero app 1.5.1 released

Ledger reacted promptly, the cooperation was nice and seamless, and I enjoyed the work with them. I was also awarded under the bug bounty program.

------------------------------------------------------------------------------------------------------------- 

## Extras

Few interesting PoC improvements and observations follow.
 
### sc_sub removal is not enough

The function `sc_sub` is not used by the Monero wallet. Thus one simple countermeasure would be to remove `sc_sub` from the Ledger Monero app. But as we show, it is easy to simulate `sc_sub` with the `sc_add` in the following way.

It holds that \\(lx = 0 \; (\text{mod} \; l) \\), where l is the curve order. Thus \\((l-1)x = -x \; (\text{mod} \; l)\\). 

We show an algorithm that can be used to generate a sealed version of an arbitrary scalar value \\(x\\).  

1. Call [`monero_apdu_generate_keypair`](https://github.com/ph4r05/blue-app-monero/blob/7d6c5f5573c4c83fe74dcbb3fe6591489bae7828/src/monero_key.c#L479) to obtain sealed scalar \\(\widehat{a}\\) and public point A.
2. Use decrypt oracle to obtain \\(a\\), so we have plaintext-ciphertext pair.
3. As value of \\(a\\) is known, finds it's multiplicative inverse \\(a^\{-1\}\\).
4. Construct a *base* \\(\mathcal{B} = \\{ \widehat{2^ia}, i \in [1, 255] \\} \\) by calling `sc_add`. E.g., \\(\text{sc\_add}(\widehat{a}, \widehat{a}) = \widehat{2a}\\), \\(\text{sc\_add}(\widehat{2a}, \widehat{2a}) = \widehat{4a}\\), etc. 254 function calls to sc_add is needed.
5. Construct set \\(\mathcal{I} = \\{i \; \| \; 2^i \; \\% \; xa^\{-1\} = 0 \\}\\), i.e., positions where binary representation of \\((xa^\{-1\})\\) has ones. 
6. Use addition to compute: \\(\sum\_\{i\in\mathcal{I}\} \mathcal{B}\_i = \sum\_\{i\in\mathcal{I}\} \widehat{2^ia}\\)
 = \\(\widehat{a(l-1)a^\{-1\}} = \widehat{x}\\)
 
Thus we obtain an *encrypting oracle*, i.e., we can construct a valid sealed version of a known scalar. The base \\(\mathcal{B}\\) is independent on the input \\(x\\) ad thus can be reused.

This algorithm can also be used to obtain encryption of zero or get negative value of unknown scalar \\(y\\) obtained from the protocol results if we construct the base \\(\mathcal{B} = \\{ \widehat{2^iy}, i \in [1, 255] \\} \\), then define the set \\(\mathcal{I} = \\{i \; \| \; 2^i \; \\% \; (l-1) = 0 \\}\\), i.e., binary representation of the \\(l-1\\). Then \\(\sum\_\{i\in\mathcal{I}\} \mathcal{B}\_i = \sum\_\{i\in\mathcal{I}\} \widehat{2^iy}\\) = \\(\widehat{y(l-1)} = \widehat{-y} \; (\text{mod} \; l) \\).

### PoC v2, more general

We wanted to design a more general PoC that would underline the true problem of the protocol that would survive several simple countermeasures such as removal of sc_add and sc_sub functions. The primary problem is the reuse of the alpha parameter in the `mlsag_sign` which should be random and never reused.

Here follows the more general [PoC v2](https://github.com/ph4r05/ledger-app-monero-1.42-vuln/blob/3e615bbfe4c4112ddc9e4099a1ba8378f37ab90b/poc.py#L205), which is described later.

1. Get \\(A\\) (public view key) from the Ledger or the wallet address (doable off-line).
2. Find a scalar \\(x\\), while the following holds:
     - \\(Pb = \text{encode\_point}(8xaG)\\), where \\(P = 8xaG = 8xA\\)
     - \\(Pb = \text{encode\_scalar}(\text{decode\_scalar}(Pb))\\)
     - i.e., the encoding \\(Pb\\) of the point \\(P\\) can be interpreted both as a EC point \\(P\\) and 
     as a scalar \\(p\\) (without modular reduction required)
     - This is performed off-line, in the PoC, card interaction is not required as we have \\(A\\)
3. Call [`monero_apdu_generate_key_derivation`](https://github.com/ph4r05/blue-app-monero/blob/7d6c5f5573c4c83fe74dcbb3fe6591489bae7828/src/monero_key.c#L510)\\((xG, \text{C_FAKE_SEC_VIEW_KEY})\\) to obtain \\(\widehat{8a(xG)} = \widehat{P}\\). We thus know plaintext-ciphertext pair for a known point \\(P\\).
4. Call [`monero_apdu_derive_secret_key`](https://github.com/ph4r05/blue-app-monero/blob/7d6c5f5573c4c83fe74dcbb3fe6591489bae7828/src/monero_key.c#L574)\\((\widehat{P}, 0, \text{C_FAKE_SEC_SPEND_KEY})\\) to get \\(\widehat{s} = \widehat{\mathcal{H}\_s(P\|\|0) + b}\\), where \\(b\\) is the spend key.
5. Call [`mlsag_hash(p2=1, opt=0x80)`](https://github.com/ph4r05/blue-app-monero/blob/7d6c5f5573c4c83fe74dcbb3fe6591489bae7828/src/monero_mlsag.c#L72), which returns \\(c\\) as plaintext scalar.
6. Call [`mlsag_sign`](https://github.com/ph4r05/blue-app-monero/blob/7d6c5f5573c4c83fe74dcbb3fe6591489bae7828/src/monero_mlsag.c#L96)\\((\widehat{s}, \widehat{p})\\)
     - We obtain \\(r = s - cp = (\mathcal{H}\_s(P\|\|0) + b) - c*(8xaG)\_{\text{scalar}}\\)
     - Note the \\(p\\) is now decoded as a scalar value, thus \\(p=(8xaG)\_{\text{scalar}}\\) is scalar value obtained by decoding the serialized EC point \\((8xaG)\\) as scalar. We know the cleartext value of \\(p\\) from construction.
     - Compute the master spending key \\(b\\) as \\(b = r - \mathcal{H}\_s(P\|\|0) + cp\\)
     - We can compute \\(\mathcal{H}\_s(P\|\|0)\\) as \\(P\\) plaintext value is known.

### Notes

As encryption of scalars and points are the same, we can use this *type confusion* to find a value that can be interpreted in both ways, i.e., a valid EC point and a valid Ed25519 scalar. This is useful to construct a derivation, which is basically ECDH derivation, which goes encrypted to the `monero_apdu_derive_secret_key`. Note there is only function `monero_apdu_generate_key_derivation` that returns encrypted EC points. 
The same value of P is in step 6 used as a known scalar to obtain decrypting oracle.

According to the [numerical simulation](https://github.com/ph4r05/ledger-app-monero-1.42-vuln/blob/master/poc_sim.py), the \\(E\[\text{steps\_finding\_x}(A)\] = 15\\), i.e., 
on average in 15 steps we find suitable \\(x\\) value. Which corresponds to a fact that EC points are distributed more/less equally on the 32 bytes (256 bits). The scalars occupy 252 bits which gives \\(2^{256-252}=16\\).

The attack uses an only small set of functions, all function calls besides the last one `mlsag_sign()`
are legit and could appear in the normal transaction construction process. It is thus hard to prevent
this from working. Used functions:
```python
reset()
set_mode()
open_tx()
gen_derivation()
derive_secret_key()
mlsag_hash()
mlsag_sign()
```

## Observations

- Scalars / points can be used interchangeably in the protocol. This *type confusion* 
is a significant vulnerability. Especially when the attacker manages to obtain known 
plaintext-ciphertext pair, which can then later be used in both contexts (scalar, point).
Knowing the plaintext value is important for the computation of `Hs(P||0)` and `c*P` elimination.

- When the view key is extracted (for faster blockchain scanning), the leak of a plaintext-ciphertext
pair cannot be prevented for scalars, as the attacker knows `a` and can use `C_FAKE_SEC_VIEW_KEY` to make
Ledger computes scalars with `a`. E.g., `monero_apdu_derive_secret_key(deriv, idx, a)` can be 
used to construct scalar plaintext-ciphertext pair. 
 
- `mlsag_sign` is important for all attacks as it returns an unencrypted scalar value from
originally encrypted scalar inputs. It is used as a decryption oracle.


## Countermeasures

To make the protocol secure against the mentioned family of attacks the aforementioned 
weak spots have to be eliminated.


### Remove simple scalar functions

As correctly proposed by the Ledger, removing `sc_sub()` and `sc_add()` helps significantly. 
As demonstrated in the previous report, the attacker can construct many usable scalar values that
can be later used in the attack. 

### User confirmation / notification

- As the HMAC key is changed with each new transaction, the user should be explicitly asked to confirm the transaction signing process once `open_tx()` is called in the real transaction mode. I.e., Ledger should ask the user whether he wants to continue
with the transaction signature. The user confirms by pressing a button. 

- User confirmation is required to mount any attack. Attack surface is thus reduced 
to the point when the user is actively sending a new transaction, the time window is 
significantly reduced.

- Ledger should display information on the display when `open_tx` was called, even for fake
transactions (used during the transaction assembly process, can be called several times before a real transaction that meets the requirements is assembled). Any display change would be nice, so the user is able to notice that Ledger is
performing some tasks. 

- When the transaction is finished with error (e.g., some security assertion fails), the user should be notified on the screen and optionally asked for confirmation to continue in normal operation. The attacker thus cannot just flash the error message over a short period of time
without the user noticing. 

- Some other attacks we considered require more transaction openings so limiting it 
by requiring the confirmation lowers the attack surface significantly.


### Proper input validation

- If any assertion fails (non-reduced scalar, EC point not lying on the curve), abort the transaction, reset keys, notify the user and ask for confirmation to continue.
- Stronger requirement: if the assertion fails, ask for PIN re-entry.


### Symmetric key hierarchy

This is the primary countermeasure that blocks all attacks we considered. 
For the sake of simplicity, we will assume just HMAC keys for now and address `spk` key later.

- The HMAC key `hk` is changed with each new transaction (as now)
- HMAC key used for particular parameters is derived from `hk` based on the following
   - Value type, scalar or point
   - Content-type, derived secret or random scalar mask
   - Function calling context. e.g., alpha in mlsag_sign.
- Encrypted values are thus usable only in a particular context, i.e., the context with the same HMAC key.
- This also prevents the *type confusion*.  
   
Example:
- HMAC key for EC points - derivation: `H(hk || "0")`.  
- HMAC key for scalars: `H(hk || "1")`
- HMAC key for random scalar masks alpha: `H(hk || "2")`
- HMAC key for amount key: `H(hk || "3")`

Other EC points than derivations are not exported in an encrypted form in the protocol. If there are more EC point types later, differentiate them.

Ideally, the encryption key should also be changed with each new transaction (random), if possible. 
Definitely, for values we are sure were produced after `open_tx()`. Thorough protocol analysis
or just simple testing will reveal which values need to have fixed `spk` key.
We would suggest to start testing this improvement with the encryption key `spk` being randomly generated after `open_tx()`.
After transaction finish/abort the key is reverted back to static `spk`. 

Different encryption key strictly limits attacker to the scope of one transaction with respect to the data confidentiality, which is useful for security arguments. I.e., no long-term analysis 
and data collection can be performed.

The specified HMAC key hierarchy is also usable for encryption, which decreases the attack surface significantly as values are valid only in a particular context. This is especially important as the initialization vector (IV) is zero = encryption has no semantic security, i.e., the same plaintexts encrypt
to the same ciphertexts. The zero IV allows the attacker to test values for equality without knowing the plaintext values.

The key hierarchy significantly restricts the potential combinations attacker can use,
restricting to explicitly allowing ones by the protocol designer.

## MLSAG Sign 

Recall \\(\text{mlsag\_sign}(\alpha, x) = \alpha - cx\\), where:
   - \\(c\\) is parameter known to attacker
   - \\(\alpha\\) is a random scalar mask
   - \\(x\\) is a secret scalar value
   
Notice that if \\(\alpha\\) is allowed to be used more than once, we have a decryption oracle: 
- \\(\text{mlsag\_sign}(\alpha_1, x_1) = r_1\\)
- \\(\text{mlsag\_sign}(\alpha_1, x_2) = r_2\\)
- \\(r_1 - r_2 = (\alpha_1 - cx_1) - (\alpha_1 - cx_2) = \alpha_1 - cx_1 - \alpha_1 + cx_2 = c(x_2-x_1)\\)
- As \\(c\\) is known, attacker can recover \\(x_2-x_1\\). If attacker knows a plaintext value for one scalar secret, 
let say \\(x_1\\) he can recover scalar value for \\(x_2\\).
- \\(x_1\\) can be constructed by calling \\(\text{monero\_apdu\_derive\_secret\_key}(P, 0, a)\\) as we usually know \\(a\\) as it was exported to the client and we know the value of \\(P\\).
- Similarly, if \\(x_1\\) is known, then \\(\alpha_1 = r_1 - cx_1\\).
- We do not consider type confusion and other attacks as those are eliminated by key hierarchy.

Monero currently uses only the `MLSAG_SIMPLE` signature scheme. The `MLSAG_FULL` is not needed with Bulletproof transactions, and thus, Ledger does not have to support it. This reduces the attack surface and simplifies countermeasures design. 
Thus it holds that `mlsag_prepare()` is called only once per signature (for non-multisig transaction),
followed by exactly one `mlsag_sign()` call (it holds dsRows==1).

We propose to extend the state by adding a `sign_counter`, which is incremented in the beginning 
of the `mlsag_prepare()` call.
The encryption and HMAC keys for \\(\alpha\\) are then derived as:
\\(\mathcal{H}(hk || \text{"alpha"} || \text{sign\_counter})\\).

This guarantees that only \\(\alpha\\) generated by the `mlsag_prepare()` can be passed to the `mlsag_sign()`
as the first \\(\alpha\\) parameter. Separation of \\(\alpha\\) and \\(x\\) domains via different keys restricts the 
attack surface.

It is easy to show that if \\(\alpha\\) is a random scalar, then the attacker can derive no information about `xx1`
from \\(\alpha - cx_1\\). The reason is that \\(\alpha\\) can be generated only in `mlsag_prepare()` and 
used only in `mlsag_sign()` as a first parameter, nowhere else.
It is essential that \\(\alpha\\) can be used only once as input to the `mlsag_sign()`. 
Otherwise, the attacker can eliminate it.
 
Thus the attacker can derive no information about \\(\alpha\\) using other functions than `mlsag_sign()` as it fails
HMAC check in those. The attacker could learn \\(\alpha\\) if he knows decryption of \\(x_1\\), but such \\(\alpha\\) is just a 
random scalar, and this knowledge cannot be reused in another `mlsag_sign()` call, making the knowledge useless.   


### Strict state model checking

Due to the low-level nature of the API functions, it is difficult to capture the 
explicit state model as the function call flow highly depends on the transaction being signed, 
i.e., a number of inputs, outputs, use of sub-addresses, UTXO (unspent transaction outputs) types - aux keys used, etc...

However, the more the state model is restricted, the lesser is the attacker space.
It is recommended to study the valid transaction construction paths and enforce obvious state transitions.

For instance, enforce a rule that the `mlsag_prepare()` has to be followed exactly by the `mlsag_hash()` 
(several times, depends on mixin, not critical to enforce number of the `mlsag_hash()` calls).
Enforce that the `mlsag_sign()` can be called only after the `mlsag_hash()` and only once per `mlsag_prepare()`.
Ideally if the `mlsag_sign()` increments the `sign_counter` as well after it computes the `ss` result, 
to enforce state change, which prevents malicious state transitions.

Client change:
Commit to the {mixin, number of UTXO, number of transaction outputs} in the initial `open_tx()` call.
Then enforce the rule that a number of calls to the `mlsag_prepare()` and `mlsag_sign()` has to be equal to the number of `UTXO` (as we have one signature per UTXO).

Note the basic state model enforcement can be done without changing the client. 
However, a more precise check requires to commit to the number of transaction inputs. 

### Conclusion

All aforementioned fixes are directly applicable on the Ledger side without the need to touch the Monero codebase.
The mentioned changes fix the whole family of attacks similar to those presented and effectively blocks the main attack vectors and leaks.

It is thus possible to fix the critical vulnerability without need to release a new Monero client version, 
which significantly speeds up the patch roll-out. 

## Client-changing countermeasures

Here follow the measures that require client modifications to work.
They improve security significantly but are not necessary to block the vulnerability. 

### Encrypt-then-reveal

We propose not to return plaintext values from `mlsag_sign()` directly, but to return encrypted versions,
under a new, transaction-specific encryption key `kse`, which is used specifically for this purpose.

After the transaction is successfully constructed, i.e., no security assertion was violated, the Ledger
returns the `kse` to the host client so it can decrypt the MLSAG signature. 

This countermeasure strictly enforces correct state transitions and blocks the attacker's reactivity.
I.e., the attacker cannot use results from the previous `mlsag_sign()` calls to adapt an attacking strategy
as he learns the result only after the protocol finishes successfully. This property is important for security proofs and to strictly guard the potential attacker space.

This change is very easy to implement and brings significant security benefits.
However, it requires a minor client code change. 

We recommend using this measure with a new Ledger Monero protocol version.
After some time (all users migrate to new Monero clients enforcing new signing protocol), the support
for unencrypted `mlsag_sign()` can be dropped. 


### Support multiple BIP derivation paths

Allow user to specify BIP derivation path (or its part) when creating the wallet from the Ledger 
device to allow multiple cryptographically separated master (view, spend) keys derived from the seed.

Ledger Monero app Version 1.4.2 has a fixed derivation path, which blocks the user from using a new set of keys with the same device seed.

For example, each user should consider current master keys leaked and dangerous to use. 
He cannot then use Ledger device without seed reset, which affects all other apps on the 
Ledger, i.e., the Bitcoin app. 

With the fixed path user also cannot transfer all funds to another safe address without using
software wallet (risk of spend key leak) or another Ledger device.

If the user can specify another path, the migration to a safe (non-leaked) account is simple.
The user creates another wallet with a different path and sweeps the old account to the new one. 


### Strict state model checking

As mentioned in the similarly named section above, the more precise checking can be done if
the `open_tx()` transaction message contains information about mixin, number of UTXOs, and transaction outputs.


## Conclusion

Ledger implemented suggested countermeasures. Follow their site for more details.




[Ledger]: https://www.ledger.com
[Monero]: https://www.getmonero.org
[Speculos]: https://github.com/LedgerHQ/speculos
[Zero To Monero]: https://web.getmonero.org/library/Zero-to-Monero-2-0-0.pdf
[vuln-repo]: https://github.com/ph4r05/ledger-app-monero-1.42-vuln
[monero-app]: https://github.com/LedgerHQ/ledger-app-monero/tree/7d6c5f5573c4c83fe74dcbb3fe6591489bae7828
[monero-ledger-support]: https://twitter.com/Ledger/status/1068127566752608256?s=20
[Ed25519]: https://eprint.iacr.org/2008/013.pdf

