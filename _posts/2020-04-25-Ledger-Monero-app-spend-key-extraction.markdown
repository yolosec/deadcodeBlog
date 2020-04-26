---
layout: post
title:  "Ledger Monero App Spend key Extraction"
date:   2020-04-25 08:00:00 +0100
categories: blog
tags: ledger monero app spend key extraction bug protocol poc
excerpt_separator: <!-- more -->

---

Due to a bug in the Monero transaction signing protocol in the Ledger Monero app 
we were able to extract master Monero spending key.

<!-- more -->

<p style="text-align: center;">
    <a href="https://twitter.com/Ledger/status/1068127566752608256?s=20">
        {% imagesize /static/monero/monero.jpeg:img/3 alt='Monero + Ledger' %}
    </a>
</p>

## Intro

[Monero] is a privacy-centric cryptocurrency protecting identity of participants and amounts being transacted.
Monero support has been added to [Ledger], cryptocurrency hardware wallet, in [November 2018][monero-ledger-support].  

<p>
<iframe width="660" height="465" src="https://www.youtube.com/embed/50VczNVR7l8?rel=0" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
</p>

### Monero basics - points and scalars

[Zero to Monero] is an excelent resource describing cryptography used in Monero from scratch. 
I recommend going through it if something is not clear in this post.

Monero is based on an elliptic curve [Ed25519]. 
Public keys are points on the Ed25519 curve \\(\mathbb{G}\\), denoted as upper-case letters. 
Point \\(G\\) is a known parameter known as the *base point*. Points form a finite [cyclic group](https://en.wikipedia.org/wiki/Cyclic_group), 
so operations of addition and subtraction are defined over points. Operation over two
points results in another point on the curve. Point are encoded to 32 bytes.
 
Scalars are integers modulo \\(l\\), i.e. \\(\mathbb{Z}^{\*}\_{l} \\), where \\(l = 2^{252}+27742317777372353535851937790883648493\\) is a curve order (number of points on the elliptic curve). 
Scalars are denoted as lower-case letters. As \\(l\\) is a prime number, \\(\mathbb{Z}^{\*}\_{l}\\) is a [finite field](https://en.wikipedia.org/wiki/Finite_field), i.e., there are addition, subtraction, multiplication and division operations defined over the scalars. 

Moreover, we have an operation called *scalar multiplication*, \\(bP = (P + P + \cdots + P) = Q\\), where \\(b \in \mathbb{Z}^{\*}\_{l}, P \in \mathbb{G}, Q \in \mathbb{G}\\). 
Scalars also work as private keys, by computing \\(bG=B\\) we get public key \\(B\\).
Scalar multiplication in non-invertible, i.e., computation of \\(b\\) from \\(B\\) is not feasible (reduces to solving [discrete logarithm problem](https://en.wikipedia.org/wiki/Discrete_logarithm)). Scalars are encoded as 32 bytes.

### Monero private keys

Monero wallet has a pair of private keys \\((k^s, k^v)\\) called spending and view key. Spending key is essential for spending owned Monero coins while view key is needed to determine whether transaction on the blockchain is for our account. Monero address contains public spend and view key, \\((k^sG, k^vG) = (K^s, K^v)\\).

Private keys \\((k^s, k^v)\\) are protected by hardware wallets in a way they never leave the device and
enables user to use them only in a predefined way, i.e., user has to confirm destination address and amount to be transacted before hardware wallet uses keys to sign the transaction. 

However, the view key \\(k^v\\) is often exported from the hardware wallet and stored in the software wallet as it is needed for common read-only Monero operations. Software wallet with the view key can scan incoming transaction, determine whether we received any funds and decode value of those funds. This can be done without having hardware wallet connected. Without exporting view key the hardware wallet would have to be connected and cryptographic operations would have to be computed over each transaction in each block, which would be quite slow. 

The view key is derived from the spend key thus the spend key \\(k^s\\) is the main secret we aim to extract from the hardware wallet. Once extracted, the wallet is compromised, attacker can transact all funds, which is game over.

## Transaction signing

Signing a Monero transaction is more complicated than Bitcoin transaction, for example. 
As hardware wallets (HWs) are resource limited hardware, they cannot sign the whole transaction at once and thus some transaction signing protocol has to be used to sign the transaction in a secure way, i.e., without leaking any secrets signing precisely what user confirms. 

Ledger application implementing such Monero signing algorithm is: [https://github.com/LedgerHQ/ledger-app-monero](https://github.com/LedgerHQ/ledger-app-monero). Documentation of the commands provided by the Monero application is [here](https://github.com/LedgerHQ/ledger-app-monero/blob/master/doc/developer/blue-app-commands.pdf).

The Monero wallet then calls given commands in order to sign the transaction. 
Ledger's transaction signing protocol runs low-level, i.e., operations provided by the HW app are usually simple commands. Operation's input and outputs are protected by AES128-CBC (zero IV) and HMAC. 
Encryption key `spk` is derived from the spend key and remains the same for the whole life of the wallet. HMAC key `hk` is random, generated for each transaction.

### Decryption oracle

The app is implemented in C, but I will show the core ideas in python for brevity.
Take a look at the [`sc_sub`](https://github.com/ph4r05/blue-app-monero/blob/7d6c5f5573c4c83fe74dcbb3fe6591489bae7828/src/monero_key.c#L430) operation:

```python
def sc_sub(a: SealedScalar, b: SealedScalar) -> SealedScalar:
    """Input: {a, b} scalars"""
    aa = hmac_and_decrypt(a, spk, hk)
    bb = hmac_and_decrypt(b, spk, hk)
    cc = (aa - bb) % l  # l is curve order
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

Resulting scalars `ss` are public part of the MLSAG signature in the transaction thus the output of `mlsag_sign` is not encrypted. Scalar `c` is part of the internal state which we know (not important now). 

Note that if we pass `x=0` to the `mlsag_sign` we obtain *decrypting oracle* as the function returns decrypted scalar value of the `alpha`. For that we need an encrypted version of a zero scalar which we can obain by calling `zero = sc_sub(x, x)` for any encrypted scalar value `x`. We can thus decrypt all private values sent over the protocol.

```python
def decrypt_oracle(x: SealedScalar) -> Scalar:
    zero = sc_sub(x, x)  # can be reused
    xx = mlsag_sign(alpha=xx, x=zero)
```

If we could just pass \\(k^s = \\) `b` to the `decrypt_oracle` we won. But there are few more steps required.

### Spend key extraction



[Ledger]: https://www.ledger.com
[Monero]: https://www.getmonero.org
[Speculos]: https://github.com/LedgerHQ/speculos
[Zero To Monero]: https://web.getmonero.org/library/Zero-to-Monero-2-0-0.pdf
[vuln-repo]: https://github.com/ph4r05/ledger-app-monero-1.42-vuln
[monero-app]: https://github.com/LedgerHQ/ledger-app-monero/tree/7d6c5f5573c4c83fe74dcbb3fe6591489bae7828
[monero-ledger-support]: https://twitter.com/Ledger/status/1068127566752608256?s=20
[Ed25519]: https://eprint.iacr.org/2008/013.pdf

