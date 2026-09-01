"""Orchestration: one QDS run, from entanglement to a transferred signature.

The six modules under :mod:`sih141.protocol` each own one step. This one owns
the *order* of the steps, and the object that remembers what happened:

.. code-block:: text

    QDSSession(params, rng=...)
        .distribute()        Phase A   k_0, k_1 drawn; both public keys
                                       teleported to Bob AND to Charlie,
                                       measured on arrival -> 4 classical logs
                                       (with check_fraction > 0, a sampled
                                       subset of positions is spent on
                                       measuring the channel instead -- see
                                       :ref:`check-rounds`)
                             Phase A'  Bob and Charlie privately re-assign
                                       their two copies of every position
                                       between themselves (symmetrisation)
        .sign(b)             Phase B   Alice declares k_b over the
                                       authenticated classical channel
        .exchange_counts()   Phase C'  Bob and Charlie announce to each other
                                       how many positions each can score,
                                       one integer each way
        .verify(Party.BOB)   Phase C   Bob scores his own log,  cut at s_a
        .transfer()          Phase C   Bob forwards to Charlie, who scores his
                                       own log, cut at s_v
        .transcript()                  the whole run as one frozen,
                                       JSON-serialisable record

``run(b)`` performs the five calls in that order and returns the transcript.

Why Phase A' is inside ``distribute()`` and not a seam of the distributor
------------------------------------------------------------------------
Symmetrisation is performed *by the recipients*, over their own authenticated
channel, after the quantum phase is over. It is what makes non-repudiation true
at all (:mod:`sih141.protocol.symmetrise`), so it must not sit anywhere an
adversary standing in Alice's place can reach: a malicious ``distributor``
returns records and the session symmetrises whatever it returns. There is a
separate ``symmetriser`` seam for Phase 3, but it replaces *the recipients'*
step, not Alice's, and the honest default is the secure one.

Phase C' has exactly the same standing. It is the recipients' own step, on the
same private channel, and its seam (``count_exchange``) replaces what *they* do,
never what Alice does. What it moves is one integer each way -- how many
positions each verifier can score against the declaration -- which is what makes
the pooled matched-count floor checkable at all: the count every repudiation
bound is exponential in is ``M = m_B + m_C``, and neither verifier knows it
alone. Without it a signer who reads both raw logs aims ``M`` at twice the
per-verifier floor, splits it with the symmetrisation coins, and leaves Bob
accepting a signature Charlie cannot score, about half the time and at every key
length. See :mod:`sih141.protocol.tally` and
:ref:`sih141.protocol.verify <pooled-floor>`.

The price is stated where it belongs, in ``tally``, but one part of it is this
module's shape: **Bob's verdict is no longer local.** He cannot accept before
Charlie has reported a count, and Charlie cannot count before he holds the
declaration, so the declaration reaches Charlie before Bob decides. A deployment
orders it so that a signature Bob would reject on his own rate is still never
forwarded; a signature he would accept is simply no longer accepted on his own
evidence alone.

Why Charlie is in the constructor and not an option
---------------------------------------------------
Every claim the scheme makes is a claim about a *second* verifier.
Transferability is "Bob accepted **and** Charlie accepted"; non-repudiation is
the impossibility of "Bob accepted **and** Charlie did not". Neither statement
is even expressible with one recipient, so a session always distributes to both
:data:`~sih141.protocol.params.VERIFIERS` and there is no knob to turn that off.
For the same reason both message bits are distributed for: Alice must commit to
``k_0`` and ``k_1`` before she learns which bit she will be asked to sign, so a
session that distributed only for the bit it later signs would be a session in
which Alice chose her key after seeing the message.

Cost, stated plainly: a session teleports ``2 message bits * 2 recipients * L``
qubits. With :data:`~sih141.protocol.params.DEMO_PARAMS` that is 768 hops; with
:data:`~sih141.protocol.params.DEFAULT_PARAMS`, 27648.

.. _threat-model:

The threat model, stated plainly
--------------------------------
Every bound this package quotes is a statement about one adversary, and an
adversary is defined by **what he holds**. That list used to be implicit in what
each seam happened to be handed, which is the wrong place for it: a seam handed
more than its adversary holds does not make the mathematics wrong, it makes the
measured number a number about nobody. So the model is written down here, and
the seams below are described as *places in it*.

*A repudiating Alice* holds ``k_0`` and ``k_1``, the parameter set, and
everything she did in Phase A -- her preparations, her Bell outcomes, and the
free choice of what to declare in Phase B. She does **not** hold either
recipient's measurement log, and she does **not** hold the symmetrisation coins:
those are tossed by Bob and Charlie on their own authenticated channel after her
quantum phase is over (:ref:`two-streams`). She wants Bob to accept a
declaration Charlie will reject.

*A forging recipient* -- Bob, or symmetrically Charlie -- holds his own raw log,
his own post-exchange log, the declaration once it reaches him, his own matched
count, and the single integer his counterpart announced in Phase C'. He does
**not** hold the other recipient's log, does not learn ``k_b`` before Alice
declares it, and does not know which positions the coins gave away. He wants the
*other* verifier to accept a declaration Alice never made, which makes his
attack a substitution on the hop he owns -- see :ref:`forger-route`.

*A channel adversary* owns the quantum links and the payload line: any
entanglement resource he likes per hop (``resource_factory``), and any
substitution he likes on the state Alice sends (``payload_map``). What he sees is
an entangled half that is locally maximally mixed and two uniform classical bits
(:mod:`sih141.core.teleport`), so he may degrade the delivery but cannot read the
key off the wire. He holds no private log and no coin.

*A classical-link adversary* sees and may alter the classical messages, which is
where the ``forwarder`` seam sits. The classical channel is assumed
authenticated -- that is an assumption of the scheme, not something it provides
-- but it is **not** assumed secret, and the difference has a consequence Phase 5
should read before it reads any table: an eavesdropper who copies ``(b, k_b)``
off the wire and rushes it to Charlie ahead of Bob spends Charlie's round on a
declaration that is perfectly valid, and Bob's own forward then refuses as
:attr:`~sih141.protocol.verify.AbortReason.RECORD_ALREADY_VERIFIED`.
Transferability happened, by a different courier; a
``RECORD_ALREADY_VERIFIED`` at Charlie is therefore not by itself evidence of an
attack *on* Charlie.

**Nobody in this model holds both recipients' logs at once.** That is the whole
content of Phase A': it is what makes the two verifiers' evidence different, and
what every non-repudiation statement is a statement about. A run in which some
seam was shown both is a run outside the model, and this module now makes that a
deliberate, flagged choice rather than the default -- see :ref:`two-log-signer`.

.. _phase3-seams:

The Phase 3 seams -- how attacks attach without editing this file
------------------------------------------------------------------
This module is deliberately a *scheduler*, not a policy. Every place an
adversary can stand is a keyword-only constructor argument holding a callable
that defaults to the honest implementation. Phase 3 mounts its entire attack
suite by passing different callables; **nothing in this file changes for any
attack**, which is what makes an attacked run and a clean run comparable rather
than two different programs.

``resource_factory`` -- the quantum channel
    Zero-argument callable returning the two-qubit entanglement resource for one
    hop, invoked once per position per recipient -- check rounds included, since
    nothing on this line may distinguish them -- and forwarded to
    :func:`~sih141.protocol.distribute.distribute_to_recipient`. Defaults to
    :func:`~sih141.protocol.distribute.ideal_resource`. This is where channel
    manipulation lives: a Werner or amplitude-damped pair is injected noise, a
    factory that degrades only some calls is an intermittent eavesdropper, and a
    factory closing over its own :class:`numpy.random.Generator` is a randomised
    one. Because the resource is drawn per position, the attack can vary at the
    finest granularity the protocol has.

    Forwarded *verbatim* on a run without check rounds. On a checked one the
    session wraps it, so that each check round's resource can be summarised on
    the way past (``channel_monitor``, below); the wrapper calls this seam
    identically at every position and records nothing until after it has
    returned, so what the seam sees is unchanged and no attack written against
    it behaves differently.

``distributor`` -- Phase A as a whole
    Callable with the signature of
    :func:`~sih141.protocol.distribute.distribute_public_key_with_checks`, which
    is the default; the records it produces are those of
    :func:`~sih141.protocol.distribute.distribute_public_key`, which is a
    wrapper over it, and what it adds is the check log. Replacing it replaces
    the entire distribution step for one message bit, which is where an
    impersonator standing between Alice and the recipients belongs -- one who
    substitutes his own states rather than merely degrading Alice's. Its return
    value is checked (both verifiers present, right message bit, right length)
    before the session will use it, so a mis-wired attack fails loudly instead
    of quietly producing a clean run.

    It is the one *Alice-side* seam handed a generator, because it stands where
    the quantum channel is and a channel is random. What it gets is the
    **Alice-side** stream and not the session's only one: the symmetrisation
    coins come from a second stream this seam is never shown, and cannot
    predict from the one it is shown. See :ref:`two-streams`, which is a
    threat-model boundary rather than a detail of plumbing.

``payload_map`` -- the state Alice actually sends
    Callable ``payload_map(state, context)``, forwarded verbatim to
    :func:`~sih141.protocol.distribute.distribute_to_recipient` and invoked once
    per **key round** with the eigenstate about to be teleported and the
    :class:`~sih141.protocol.distribute.ResourceContext` naming the hop. ``None``
    -- the default -- calls nothing. This is where an attack on the *payload
    line* stands, as distinct from the channel: a damped or rotated preparation,
    a substitution on one recipient's link only, a fault injected at chosen
    positions.

    It exists because the alternative was to mount such an attack from
    ``distributor``, i.e. to reimplement the whole distribution loop inside the
    attack -- a copy that drifts the first time
    :mod:`sih141.protocol.distribute` changes, and whose bugs are invisible
    because the honest path never runs it. See :ref:`sih141.protocol.distribute
    <payload-seam>`, including the two things it deliberately cannot reach: it
    is never called on a check round, and it draws no randomness.

``signer`` -- Phase B, i.e. who is holding the pen
    Callable matching :class:`Signer`, defaulting to :func:`honest_signer`. It
    receives the message bit, the key pair and the parameters, and returns the
    :class:`~sih141.protocol.signature.Signature` that will be verified. That is
    everything a repudiating Alice holds (:ref:`threat-model`), and she is the
    adversary this seam is for: she starts from her real ``k_b`` and perturbs
    it, aiming to land under ``s_a`` at Bob and over ``s_v`` at Charlie.

    **A forging recipient does not stand here** -- see :ref:`forger-route`,
    which is the correction to what this section used to say.

    .. _two-log-signer:

    *The over-powered variant, and why it is now opt-in.* The seam also takes a
    keyword-only ``records`` mapping, and it used to be handed **both**
    recipients' raw logs by default -- strictly more than any single adversary
    in the threat model holds, and the root cause of the whole repudiation
    attack family the Phase 2 audit found. It is now withheld: the default
    passes :data:`NO_RECIPIENT_LOGS`, an empty mapping that says what it is when
    something reaches into it. Construct the session with
    ``signer_sees_recipient_logs=True`` to get the old behaviour, which is a
    legitimate thing to want -- those attacks are worth measuring, and one of
    them is what the pooled floor was built against -- and a run made that way
    is flagged in the transcript
    (:attr:`SessionTranscript.signer_saw_recipient_logs`) and named out loud in
    :meth:`SessionTranscript.summary`, the way an unsymmetrised run already is.
    An insecure-arm result can then never be read as a secure-arm one.

    *Which records the opt-in hands over.* The **raw**, pre-exchange logs, not
    the post-symmetrisation ones the verifiers are scored on. That is the
    faithful choice in both directions. It is what a forging recipient needs:
    after the exchange, half of Charlie's evidence *is* Bob's own raw record, so
    declaring that record at every position is Bob's optimal strategy and
    reaches the ``1/12`` floor, whereas his post-exchange record is precisely
    the half Charlie does *not* hold and is worth nothing to him. And it is what
    a repudiating Alice must not have: the exchange is private to the
    recipients, so its outcome is never offered to whoever is holding the pen.

    Two published consequences follow from the opt-in, and they are the reason
    it is flagged rather than merely available. Neither is a defect in the
    mathematics; each is a limit on what a number from such a run may be
    published as.

    *It can empty the matched set outright.* A declaration that avoids both raw
    logs at every position leaves nothing for either verifier: after the
    exchange each verifier's entry is one of the two raw entries, and both were
    avoided, so ``|M_B| = |M_C| = 0`` with probability ``1`` -- measured 20/20
    at ``L = 600``. (Avoiding only *Bob's* log is defused by Phase A', which
    leaves ``E|M_B| = L/6``; it is the *pair* of logs that is fatal.) It forges
    nothing and repudiates nothing, since no verdict is reached, but it used to
    surface as an uncaught :exc:`ValueError` in the middle of
    :meth:`QDSSession.run` -- a verifier an attacker could crash, and a run an
    experiment harness silently lost. It is now a recorded no-verdict outcome:
    see :class:`~sih141.protocol.verify.VerificationAbort` and
    :attr:`SessionTranscript.aborts`.

    *It can starve the matched set without emptying it.* The same signer can pin
    ``|M_B| + |M_C|`` at a handful of positions for any ``L``, where honest
    operation gives ``2L/|B|``. The repudiation bound in
    :mod:`sih141.protocol.analysis`, in its default form, averages over
    ``M ~ Binomial(2L, 1/|B|)``, and that average assumes **the declared bases
    are independent of the recipients' logged bases** -- exactly the assumption
    this seam breaks. The bound *conditional* on an observed matched count is
    not violated; what would be wrong is quoting the ``M``-averaged number as if
    it held unconditionally against every signer. Phase 3 and Phase 5 should
    read the per-run conditional bound from the observed ``m_B + m_C``, which
    every transcript carries
    (:attr:`~sih141.protocol.verify.VerificationResult.matched_count`).

    *It can also aim the total and let the coins split it,* which is the subtler
    version and the one a per-verifier floor does not catch: a declaration whose
    pooled matched count is exactly ``2 m_min``, all of it correct, leaves Bob
    over his floor and Charlie under his about half the time, with no rate
    deviating anywhere. Phase C'
    (:meth:`QDSSession.exchange_counts`,
    :mod:`sih141.protocol.tally`) closes it: the pooled floor refuses the aimed
    total outright, and a verifier under his own floor takes the other down with
    him, so "Bob accepts" now implies "Charlie reached a verdict". Every verdict
    this session emits therefore rests on ``m_R >= m_min`` at *both* verifiers
    and ``m_B + m_C >= M_min``, which is what
    :func:`~sih141.protocol.verify.enforced_repudiation_bound` evaluates --
    unconditionally, and without making the averaged number unconditional.

    One further seam-reachable behaviour is plumbing rather than an attack: a
    signer returning a signature for the other bit is refused by
    :meth:`QDSSession.sign`.

``forwarder`` -- the Bob-to-Charlie classical hop
    Callable taking ``(signature, params)``, and optionally a keyword-only
    ``view``, returning the declaration Charlie actually scores; it defaults to
    :func:`honest_forwarder`, which returns its argument unchanged. This is the
    seam for an attack *between* the two verifications, and it is the reason
    :class:`SessionTranscript` carries both declarations rather than one: a run
    in which Bob and Charlie scored different declarations is now representable,
    where before Charlie's verdict was silently attributed to Bob's declaration
    and a Phase 4 statistic would have read an attacked run as a clean one.

    .. _forger-route:

    **This is where a forging recipient stands, and it is the correction to what
    this section used to say.** The old text sent a Phase 3 author to mount a
    forging Bob on the ``signer`` seam. That models the wrong adversary
    entirely: the signer's declaration goes to *both* verifiers, so Bob is
    handed his own forgery, scores it against his own log and rejects it.
    Measured on that route at ``L = 30`` over 1200 runs: Charlie accepted on
    ``0.4917`` of them -- the forgery worked -- while Bob rejected on all of
    them, both matched counts were inflated to ``2L/3`` because the declaration
    was built from a recipient's log rather than drawn independently, and
    ``transferable`` was ``True`` on 100 of 1200. A successful forgery was
    recorded as a non-transferable, non-repudiated run, so a Phase 5 table built
    on that route would understate the binding attack.

    Those four figures are a *reported* measurement at a key length too short to
    carry any claim, and nothing here recomputes them. What is checked, on a
    fixed seed at ``L = 600``, is the structural half -- Bob rejects, both
    matched counts inflate, and Charlie's verdict is identical on the two routes
    -- in ``tests/test_protocol_session.py``'s
    ``test_the_signer_route_records_a_successful_forgery_as_a_rejection``. That
    is the part a reader should take on this file's authority.

    The faithful route is here. Bob receives Alice's real declaration, scores it
    and accepts; the forwarder substitutes what *he* would have Charlie believe;
    Charlie scores that. The seam is handed his
    :class:`~sih141.protocol.records.RecipientView` -- his own two logs and his
    own matched count, and nothing of Charlie's -- so the attack is written
    directly against what the forger holds and cannot accidentally read the
    target's evidence. It asks for it by taking a required keyword-only ``view``
    parameter; a forwarder that does not is called with two arguments exactly as
    before. The idiom is one line::

        def forging_bob(signature, params, *, view):
            return Signature(
                signature.message_bit, key_from_record(view.raw_record)
            )

    Note what such a run is *not*: it is not a repudiation, and
    :attr:`SessionTranscript.repudiated` says so
    (:attr:`~SessionTranscript.forwarding_altered_signature` gates it). "Bob
    accepted and Charlie rejected" names a repudiation only when both scored the
    same declaration; when Bob himself supplied Charlie's, the run is one
    experiment about forgery and not one about Alice.

    *And one thing about it must be read carefully, because it decides which arm
    a forgery rate can be measured in.* Under the shipped pooled rule Charlie
    does not reject a substituted declaration -- he reaches **no verdict**,
    :attr:`~sih141.protocol.verify.AbortReason.COUNTS_FROM_TWO_DECLARATIONS`.
    Phase C' runs before either verdict, so the counts he holds were computed
    against Alice's declaration while he is scoring Bob's, and
    ``m_C(forwarded) + m_B(original)`` is no run's pooled count
    (:ref:`sih141.protocol.verify <one-declaration>`). The forgery therefore
    fails, but it is a **denial of transfer and not a detection**: Charlie has
    learned that two numbers disagree about their provenance, and nothing about
    the signature. Do not report it as a forgery caught -- the refusal is
    guaranteed by the harness's ordering, since this seam gives the forwarding
    party no way to supply a matching count, and a real forging Bob who
    announced a count against his own declaration would not trip it at all.
    Phase C' owns that gap (:mod:`sih141.protocol.tally`); it is recorded here
    because this is where a Phase 3 author will meet it.

    To measure the forger's *rate* -- how close a compliant recipient forger
    gets to ``s_v``, i.e. the ``1/12`` floor -- run the same forwarder with
    :func:`~sih141.protocol.tally.no_count_exchange`, the pre-pooled arm Phase 3
    already uses for the split-coin route. Charlie then scores on his own floor,
    lands near ``1/12``, and rejects.

``channel_monitor`` -- what a Phase 4 detector reads, published on check rounds only
    Callable ``channel_monitor(resource, context)`` returning a JSON-safe
    mapping of extra diagnostics, invoked **at every position** of a run whose
    parameter set has check rounds
    (:attr:`~sih141.protocol.params.ProtocolParams.check_fraction`), and not at
    all on one that has none. ``None`` -- the default -- still records the
    built-in summary of every check round's resource; the seam is for a
    detector that wants more than fidelity, purity and concurrence out of the
    pair it was given.

    It is an *observer*, not an adversary: it is handed a **copy** of the
    resource the ``resource_factory`` produced, so it can neither replace what
    is delivered nor edit it in place, and it draws no randomness. The copy is
    not fastidiousness -- a qiskit state hands out its array, and a monitor that
    wrote to the original would be a channel attack under an observer's name,
    invisible in a transcript that attributes channel behaviour to the factory.

    **Where it is invoked, and where its answer is kept, are two different
    questions, and the security content is in keeping them apart.** This seam
    used to be invoked at check-round positions only, which made *being called*
    the entire signal: whoever held it read the check set straight off its own
    call sequence -- 120 of 120 positions at ``L = 480``, no statistics
    involved -- and the declared channel-side adversary holds this seam
    alongside ``resource_factory`` and ``payload_map``. So it is now called
    everywhere and its answer discarded at key positions. What must stay true
    is the other half of the argument, and it does: a per-position record about
    the rounds the key is made of would stop the sampled estimate being a
    sample of anything, so the session **records** nothing at a key position,
    ever, and :attr:`SessionTranscript.channel` is checked against the
    published :attr:`SessionTranscript.check_logs` on the way back in from
    JSON, so a transcript that claims otherwise does not reconstruct. A monitor
    that wants to accumulate per-position state of its own is free to -- it is
    the recipients' detector, not the adversary's -- but nothing it accumulates
    reaches the transcript except through the check rounds.

    What comes out is a :class:`ChannelSample` per check round per recipient per
    message bit, carried in the transcript beside the
    :class:`~sih141.protocol.checkrounds.CheckLog` that holds the two wings'
    outcomes for the same positions. Between them a Phase 4 detector has the
    resource that was delivered and what measuring it produced.

    *What is deliberately not here, since it was asked for.* A key round's
    :class:`~sih141.core.teleport.TeleportationResult` carries a Bell outcome,
    two correction bits and a fidelity, and this module throws all three away.
    None of them belongs in a transcript. A check round has no teleportation at
    all, so on the rounds that may be published they do not exist. And on the
    rounds where they do exist they are either useless or unobtainable: the Bell
    outcome and its correction bits are *already public* -- Alice transmits them
    -- and are uniform and independent of the payload
    (:mod:`sih141.core.teleport`), so they say nothing; while the per-hop
    fidelity is computed from the payload and the received state together, which
    is a comparison **no party in the protocol can make**. A detector reading it
    would be reading a simulator's oracle, would report a number no deployment
    could reproduce, and would be strictly better than the scheme it is meant to
    be monitoring. The sampled check rounds are the honest source of the same
    information, and their price -- a shorter key -- is the price of it being
    honest.

.. _two-streams:

Two streams: Alice's generator and the recipients'
--------------------------------------------------
A seam is isolated only as far as the objects it is handed, and one object this
file used to hand out was the session's single generator. ``distributor`` is
given an ``rng`` -- it stands where the quantum channel is, and a channel is
random -- and Phase A' then drew its ``L`` symmetrisation coins from that same
generator object, two lines later. A distributor that cloned
``rng.bit_generator.state`` on entry therefore held every coin before the
recipients tossed them, and a ``signer`` sharing that clone with it could
declare, position by position, the eigenvalue the coin was about to hand Bob.
Measured through otherwise unmodified code at
:data:`~sih141.protocol.params.DEFAULT_PARAMS`: Bob's mismatch rate ``0.00000``
and Charlie's ``1.00000``, with ``m_B = m_C = 37095`` and ``M = 74190`` clearing
both floors, five runs out of five -- a recorded repudiation on a run whose
transcript printed ``P(repudiation | this run) <= 1.414e-09``.

Nothing there is a defect in the bound. The Hoeffding argument assumes the coins
are private, and a real Alice has no way to read a coin two other people toss on
their own authenticated channel, so the mathematics stands exactly as written.
The defect is in the *harness*: it let an Alice-side seam read them. Every
attack number this repository publishes comes out of this harness, so those
numbers were right only by the convention that the attack implementations
happened not to peek -- and nothing enforced the convention.

The constructor therefore splits the generator it resolves into labelled
streams, and a seam is handed at most one of them:

``self._alice_rng``
    Key generation and the ``distributor`` seam: everything Alice does, and
    everything an adversary standing in her place may see.
``self._recipient_rng``
    Everything the *recipients* decide for themselves. Two things now draw from
    it: the symmetrisation coins, and the check-round plan -- which positions of
    each distribution are spent on measuring the channel (:ref:`check-rounds`).
    Both belong here for the same reason. A coin Alice could predict would
    empty the non-repudiation bound; a check position Alice could predict would
    empty every channel estimate, because a party who knows which rounds are
    watched behaves on exactly those. It is built in the constructor, passed to
    the ``symmetriser`` seam -- the recipients' own step -- and to
    :func:`~sih141.protocol.checkrounds.draw_check_plan`, and is reachable from
    no accessor, no record and no transcript.
``self._binding_rng``
    The session openings, and nothing else. Handed to no seam at all; see
    :data:`_BINDING_STREAM_LABEL` for why it is a third stream rather than a
    third use of the first.

All of them come from the caller's generator: 32 bytes of material are drawn
from it once, at construction, and each stream is seeded with a SHA-256 digest
of that material under its own label (:func:`_derive_stream`). The split holds in the
direction that matters. Rewinding the Alice-side generator -- PCG64's transition
is invertible, so ``advance(-n)`` is available to an adversary -- reaches only
earlier states of *that* stream, and its ``bit_generator.seed_seq.entropy`` is
the digest rather than the material, so neither the state nor the seed sequence
of the stream a seam holds says anything about the stream it does not. The
caller's own generator is used for that one draw and then dropped, so no seam
ever holds it either. Determinism is untouched: one seed gives one material,
hence the same streams and the same transcript byte for byte
(``tests/test_protocol_session.py`` pins each of them).

One consequence is a small gain rather than a cost. With the coins out of
Alice's stream, a run made with
:func:`~sih141.protocol.symmetrise.no_symmetrisation` and one made with the
honest exchange now draw the *identical* Alice stream, so the two arms of that
Phase 3 comparison differ in one callable and in nothing else -- which is what
:mod:`sih141.protocol.symmetrise` already claimed for them, and what the coin
draw sitting in the shared stream used to spoil for the second message bit.

The rest of the seams, audited for the same class of leak:

* ``signer`` gets no generator, and is called after Phase A' has drawn its
  coins. By default it is handed no recipient log at all
  (:data:`NO_RECIPIENT_LOGS`); with ``signer_sees_recipient_logs=True`` it is
  handed the **raw** logs, which is the deliberate over-provision documented at
  :ref:`two-log-signer` and flagged in the transcript. Either way the
  post-exchange records and the coins that produced them are never offered.
* ``forwarder`` gets no generator and, unless it asks for one, no record. A
  forwarder that takes a ``view`` is handed **one** recipient's
  :class:`~sih141.protocol.records.RecipientView` -- Bob's, since Bob owns this
  hop -- which is a type that cannot hold the counterpart's evidence
  (:ref:`sih141.protocol.records <recipient-view>`). ``count_exchange`` gets no
  generator and no record; two integers pass through it.
* ``resource_factory`` and ``payload_map`` get a
  :class:`~sih141.protocol.distribute.ResourceContext` -- party, message bit,
  position -- and no generator, so a channel-side adversary cannot reach the
  coins even indirectly. A seam that wants randomness closes over its own
  generator, which is the documented way (D6).
* ``channel_monitor`` gets a resource and a context, no generator, and is
  invoked at every position alike, so that its call sequence says nothing about
  where the recipients' own stream put the check rounds. It can read the
  channel it is shown and nothing else, it cannot change what is delivered, and
  what it returns is published only at the check positions.
* ``symmetriser`` *is* handed ``self._recipient_rng``, which is correct: it
  replaces the recipients' step and the coins are theirs. It is the one seam
  from which the coins are readable -- and, by rewinding, the check plan drawn
  from the same stream a moment earlier, which is equally theirs: the
  recipients chose it. Reading your own coins is not an attack; a Phase 3 run
  that replaces this seam is running the recipients dishonestly, which is what
  :func:`~sih141.protocol.symmetrise.no_symmetrisation` already makes visible in
  the transcript. What matters is the direction: nothing on Alice's side of the
  split can rewind into either.

What none of this defends against is an attack handed the seed by the harness
that built it: a Phase 3 experiment that closes over the same
``default_rng(seed)`` it passes to the session can predict every stream in it.
No boundary inside this file can stop that, which is precisely why a Phase 3
attack should take its own generator rather than reach for the session's.

Everything downstream of the seams is fixed: the matched/unmatched split, the
three matched-count floors, the two thresholds and the accept rule are computed
by :func:`~sih141.protocol.verify.verify` from the record, the declaration, the
counterpart's reported count and the parameter set alone, so no adversary can
reach them. Phases A' and C' are likewise not Alice-side seams, and Phase A' now
draws its coins from a generator no Alice-side seam is given; see above.

A verifier whose evidence falls below one of those floors reaches **no verdict** --
neither an acceptance nor a rejection. :meth:`QDSSession.run` records it and
carries on, so a starved declaration costs a verdict rather than the whole run,
and :class:`SessionTranscript` keeps verdicts and refusals in separate fields
(:attr:`~SessionTranscript.results` and :attr:`~SessionTranscript.aborts`) so
that no Phase 4 or Phase 5 statistic can conflate the two.

.. _check-rounds:

Check rounds: which parameters shorten which key
------------------------------------------------
A parameter set with
:attr:`~sih141.protocol.params.ProtocolParams.check_fraction` greater than zero
spends ``check_count`` of its ``L`` positions on measuring the channel instead of
on key. The session then does three things it does not otherwise do, and each has
one right answer:

* **The plan is drawn from the recipients' stream**, once per message bit, by
  :func:`~sih141.protocol.checkrounds.draw_check_plan`. Never from Alice's. The
  entire value of a sampled estimate is that the party being estimated cannot
  choose the sample, and the same stream separation that keeps the coins away
  from her (:ref:`two-streams`) is what keeps the check positions away from her
  too. One draw reserves the positions for both links and deals the rounds
  between them, so the two links do not run the same check set
  (:ref:`sih141.protocol.checkrounds <check-round-links>`): a run distributes
  to Bob and then to Charlie, and a shared check set would mean an adversary
  who recovered it on the first pass could spare exactly those positions on the
  second. Each link publishes half of ``check_count`` rounds as a result.
* **Alice still draws a full-length key** and is still asked to distribute all
  ``L`` positions, because she does not know the check set when she draws. What
  she *declares* in Phase B is the sifted key,
  :meth:`~sih141.protocol.checkrounds.CheckRoundPlan.sift_key` of it, which is
  the only thing the recipients can score: the check positions carry no key
  because their pairs were spent on measurement.
* **Everything downstream is scored under**
  :meth:`params.sifted() <sih141.protocol.params.ProtocolParams.sifted>`, whose
  ``key_length`` is the ``signing_length``. Both matched-count floors and the
  repudiation bound are derived from it, so a run that scored a shortened key
  against floors sized for ``L`` would be quoting evidence it does not have.
  :attr:`QDSSession.scored_params` is that set, and it is ``params`` itself
  whenever there are no check rounds -- which is why turning the feature off
  leaves every seeded transcript in this project byte-identical.

The transcript keeps the *unsifted* parameter set, so it still records that the
run reserved a check fraction at all, and re-derives the sifted one wherever it
checks a verdict against the run's own parameters.

What the session is not
-----------------------
Not a channel and not a detector. It holds no quantum state at any point -- by
the time :meth:`QDSSession.distribute` returns, every teleported qubit has been
measured and discarded and the session's memory is four tables of integers
(:mod:`sih141.protocol.records`) plus, on a checked run, the published check
logs and one :class:`ChannelSample` per check round. Detection statistics are
Phase 4's job and read a :class:`SessionTranscript`; this module's job is to put
in it, and only in it, what a detector is entitled to see.

It *is*, now, a ledger -- of one specific thing. Each verifier holds a
:class:`~sih141.protocol.verify.ConsumedRecords` of the distribution rounds he
has already decided, and :meth:`~QDSSession.verify` hands each verifier his own
and nobody else's. That is the replay defence, and it changed a documented
promise: verifying the same party twice used to recompute the same verdict and
now refuses as
:attr:`~sih141.protocol.verify.AbortReason.RECORD_ALREADY_VERIFIED`. One
distribution round yields one verdict per verifier;
:ref:`sih141.protocol.verify <replay>` says why, and what it costs.

The application-level ledger is still somebody else's, and it still needs
something to key on. Content is not it: two runs made with the same seed produce
byte-identical transcripts, by design and by test, so a content hash cannot tell
a replay from a legitimate repeat. So a session takes an optional ``run_id``,
carried verbatim into the transcript and used by nothing here. It is
deliberately caller-supplied rather than generated: a generated identifier would
either be random -- breaking the reproducibility that Phase 5 rests on -- or
derived from the seed, in which case it would repeat exactly when a replay does
and defeat its own purpose. The harness that owns that ledger owns the
namespace. Distinct from :attr:`QDSSession.session_ids`, which is *this* run's
per-bit round identifier, is derived rather than supplied, and is the thing the
verifiers actually check.

Notes
-----
Single use (replay)
    A session distributes once and signs once. A second
    :meth:`~QDSSession.distribute` or a second :meth:`~QDSSession.sign` is
    refused, because the security of the scheme rests on the public key states
    being consumed: signing both bits against one distribution would hand a
    verifier two declarations scored against logs that are not independent of
    each other. Build a new session per run.

    Each *verification* is single-use too, for the same reason and by the same
    logic one level down: see :meth:`~QDSSession.verify`.
Determinism (D3)
    One keyword-only ``rng``, resolved once in the constructor through
    :func:`sih141.core.rng.resolve_rng`. It is drawn from exactly once, for the
    32 bytes of material the two session streams are derived from
    (:ref:`two-streams`); the Alice-side stream is then threaded through key
    generation and both distributions in that order, and the recipient-side
    stream through both check-round plans and both symmetrisations. Deriving
    rather than sharing is a threat-model requirement, not a stylistic one, and
    it costs nothing here:
    the same seed still reproduces the entire transcript, byte for byte through
    :meth:`SessionTranscript.to_json`, and ``tests/test_protocol_session.py``
    pins that.
Canonical state type (D1), qubit ordering (D2)
    Inherited from :mod:`sih141.protocol.distribute`; nothing here touches a
    state.
No machine learning (D4)
    Nothing is learned, fitted or thresholded from data. The two cuts come from
    :class:`~sih141.protocol.params.ProtocolParams` and were fixed before the
    run started.

See Also
--------
sih141.protocol.distribute.distribute_public_key_with_checks : Phase A, both
    recipients, with the check-round diagnostics.
sih141.protocol.checkrounds : What those diagnostics mean and how to estimate
    from them.
sih141.protocol.signature.sign : Phase B.
sih141.protocol.verify.verify : Phase C, one verifier.

Examples
--------
>>> import numpy as np
>>> from sih141.protocol.params import ProtocolParams
>>> from sih141.protocol.session import QDSSession
>>> params = ProtocolParams(key_length=24)
>>> transcript = QDSSession(params, rng=np.random.default_rng(0)).run(1)
>>> transcript.transferable
True
>>> transcript.bob.rate, transcript.charlie.rate
(0.0, 0.0)
"""

from __future__ import annotations

import hashlib
import inspect
import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, Protocol

import numpy as np
from qiskit.quantum_info import DensityMatrix, partial_trace

from sih141.core.rng import resolve_rng
from sih141.core.states import (
    BellState,
    StateLike,
    as_density,
    bell_state,
    concurrence,
    fidelity,
    purity,
)
from sih141.protocol.analysis import repudiation_bound
from sih141.protocol.checkrounds import (
    _ALICE_QUBIT,
    _RECIPIENT_QUBIT,
    CheckLog,
    CheckRole,
    CheckRoundPlan,
    ChshRound,
    QberRound,
    draw_check_plan,
)
from sih141.protocol.distribute import (
    PayloadMap,
    RecipientDistribution,
    ResourceContext,
    ResourceFactory,
    _draw_resource,
    _resolve_factory,
    distribute_public_key_with_checks,
)
from sih141.protocol.keys import PrivateKey, generate_key_pair
from sih141.protocol.params import (
    DEMO_PARAMS,
    VERIFIERS,
    Party,
    ProtocolParams,
    _as_message_bit,
    _as_party,
)
from sih141.protocol.records import RecipientRecord, RecipientView
from sih141.protocol.signature import (
    Signature,
    fresh_opening,
    session_identifier,
    sign,
)
from sih141.protocol.symmetrise import Symmetriser, symmetrise_records
from sih141.protocol.tally import (
    CountExchange,
    MatchedCountMessage,
    PooledMatchedCounts,
    exchange_matched_counts,
    matched_count_message,
)
from sih141.protocol.verify import (
    AbortReason,
    ConsumedRecords,
    MatchedSetTooSmall,
    VerificationAbort,
    VerificationResult,
    minimum_matched_count,
    minimum_pooled_matched_count,
    verify,
)

__all__ = [
    "COUNTS_AFTER_FORWARDING",
    "COUNTS_BEFORE_FORWARDING",
    "COUNT_EXCHANGE_TIMINGS",
    "MESSAGE_BITS",
    "NO_RECIPIENT_LOGS",
    "ChannelMonitor",
    "ChannelSample",
    "Distributor",
    "Signer",
    "Forwarder",
    "WithheldRecords",
    "honest_signer",
    "honest_forwarder",
    "forwarder_wants_view",
    "SessionTranscript",
    "QDSSession",
]


COUNTS_BEFORE_FORWARDING: Final[str] = "before-forwarding"
"""Phase C' runs before the hop; both counts name the declaration Alice signed.

The shipped ordering and the default. Bob's acceptance is not local under it --
he waits for Charlie's count -- but Charlie necessarily holds Alice's
declaration by the time he answers, so the two counts are one experiment.

Its security consequence is the one nobody wrote down until Phase 3 measured
it: an adversary who alters the declaration *on the hop* is caught by the
provenance check, because Charlie's own count was taken against what Alice
signed while he is looking at what the hop delivered. That closes the ledger's
denial-of-service surface -- and closes it as a side effect of when the step
runs, not because anything decided to.
"""

COUNTS_AFTER_FORWARDING: Final[str] = "after-forwarding"
"""Phase C' runs after the hop; each recipient counts what he actually received.

The deployment reading, and the only one available when the hop and Charlie are
separated in time. It is strictly weaker and is offered so that the weakness can
be *measured* rather than argued about:

* a **third party** on the hop still trips the provenance check, because Bob's
  count names Alice's declaration and Charlie's names the substitute. Neither
  verifier reaches a verdict, and a refusal spends no round.
* a **forging Bob** does not, because he computes his own count against the
  declaration he forwards. Both digests agree, Charlie scores the forgery on its
  merits, and the recipient-forgery rate of the *shipped* protocol becomes
  measurable for the first time. That is the arm
  :mod:`sih141.attacks.forgery` could previously only reach with
  :func:`~sih141.protocol.tally.no_count_exchange`.

Under this timing :meth:`QDSSession.verify` cannot run before
:meth:`QDSSession.forward`: Bob's pooled floor needs a count Charlie cannot
compute until he holds a declaration. :meth:`QDSSession.run` orders it.
"""

COUNT_EXCHANGE_TIMINGS: Final[tuple[str, str]] = (
    COUNTS_BEFORE_FORWARDING,
    COUNTS_AFTER_FORWARDING,
)
"""The two orderings :class:`QDSSession` accepts, in order of strength."""

MESSAGE_BITS: Final[tuple[int, int]] = (0, 1)
"""The message bits a session distributes for, in order.

Both of them, always: Alice commits to ``k_0`` and ``k_1`` before she learns
which bit she will sign (see the module docstring).
"""


# --------------------------------------------------------------------------- #
# The two session streams (see :ref:`two-streams`)
# --------------------------------------------------------------------------- #


_STREAM_MATERIAL_BYTES: Final[int] = 32
"""Bytes drawn from the caller's generator to derive the session's two streams.

One draw, in the constructor, and the caller's generator is then dropped. Thirty
two bytes because that is the width of the digest each stream is seeded with;
fewer would be the real seed length whatever the digest claimed.
"""

_ALICE_STREAM_LABEL: Final[bytes] = b"sih141.protocol.session/alice"
"""Domain separator for the stream Alice and her seams draw from."""

_RECIPIENT_STREAM_LABEL: Final[bytes] = b"sih141.protocol.session/recipients"
"""Domain separator for the stream Bob and Charlie's coins come from.

Distinct from :data:`_ALICE_STREAM_LABEL` and hashed with the same material, so
the two streams are independent for anyone who cannot invert SHA-256. Changing
either label changes every seeded transcript in the project, which is why they
are named constants rather than literals at the call site.
"""

_BINDING_STREAM_LABEL: Final[bytes] = b"sih141.protocol.session/binding"
"""Domain separator for the stream the session openings are drawn from.

A third label rather than a third *place to draw from the first*: the openings
that name a run's distribution rounds (:ref:`sih141.protocol.signature
<session-binding>`) have to come from somewhere, and taking them from the Alice
stream would shift every subsequent draw and change every seeded transcript in
the project for a value none of them depend on. Deriving a stream instead costs
one SHA-256 and leaves the other two byte-identical, which is what keeps "the
same seed reproduces the run" true across this change.

It is also the stream no seam is ever handed. That is not load-bearing -- Alice
knows her own openings, and they are revealed in Phase B anyway -- but it means
a ``distributor`` cannot read the opening of the *other* message bit, which is
the one that stays sealed.
"""


def _derive_stream(material: bytes, label: bytes) -> np.random.Generator:
    """Derive one labelled generator from the session's seed material.

    The mechanism behind :ref:`two-streams`. The generator is seeded with
    ``SHA-256(label + b":" + material)``, so that the two streams a session runs
    are reproducible from one seed and yet unpredictable from each other: what a
    seam holding one of them can read -- its ``bit_generator.state``, which
    rewinds only within its own stream, and its
    ``bit_generator.seed_seq.entropy``, which is the digest -- is a preimage
    problem away from the material, and therefore from the other stream.

    Parameters
    ----------
    material : bytes
        The session's seed material, drawn once from the caller's generator.
    label : bytes
        The stream's domain separator, :data:`_ALICE_STREAM_LABEL` or
        :data:`_RECIPIENT_STREAM_LABEL`.

    Returns
    -------
    numpy.random.Generator
        A fresh PCG64 generator, deterministic in ``(material, label)`` and
        independent of every other label's.

    Notes
    -----
    Deliberately *not* :meth:`numpy.random.Generator.spawn` or a
    :class:`numpy.random.SeedSequence` child. Both leave the parent's entropy
    sitting in the child's ``seed_seq.entropy`` in clear, so a seam holding one
    child could rebuild the seed sequence and spawn its sibling -- which is the
    very leak this split exists to close. A digest is one-way; a spawn key is
    not.

    D3 forbids reaching for :func:`numpy.random.default_rng` at a call site
    because that *restarts* a stream where one should have been threaded. This
    call is the opposite: it happens once, in the constructor, from the
    generator :func:`~sih141.core.rng.resolve_rng` has already resolved, and
    each generator it returns is then threaded through the whole run. If a
    second module ever needs a private sub-stream, this function belongs beside
    :func:`~sih141.core.rng.resolve_rng` in :mod:`sih141.core.rng`; it lives
    here while it has one caller.

    Examples
    --------
    >>> import hashlib
    >>> from sih141.protocol.session import _derive_stream
    >>> material = bytes(32)
    >>> _derive_stream(material, b"one").bytes(4) == _derive_stream(
    ...     material, b"one"
    ... ).bytes(4)
    True
    >>> _derive_stream(material, b"one").bytes(4) == _derive_stream(
    ...     material, b"two"
    ... ).bytes(4)
    False
    >>> seeded = _derive_stream(material, b"one")
    >>> seeded.bit_generator.seed_seq.entropy == int.from_bytes(
    ...     hashlib.sha256(b"one:" + material).digest(), "big"
    ... )
    True
    """
    digest = hashlib.sha256(label + b":" + material).digest()
    return np.random.default_rng(int.from_bytes(digest, "big"))


# --------------------------------------------------------------------------- #
# What the signer seam is shown (see :ref:`two-log-signer`)
# --------------------------------------------------------------------------- #


class WithheldRecords(Mapping[int, Mapping[Party, RecipientRecord]]):
    """An empty records mapping that says why it is empty.

    What :meth:`QDSSession.sign` hands the :class:`Signer` seam by default. It
    is a real, empty :class:`~collections.abc.Mapping`: ``len`` is ``0``,
    iteration yields nothing, and ``.get(bit, {})`` returns ``{}``, so an honest
    signer and a defensively-written one both behave exactly as they did when
    the parameter was a plain dictionary.

    What it adds is the message on the way out. A signer that reaches for
    ``records[b][Party.BOB]`` used to get the log; with a plain ``{}`` it would
    get ``KeyError: 0``, which says nothing about *why*. This raises a
    :exc:`KeyError` naming the constructor flag that would supply the logs and
    the reason the default does not -- because "the seam was silently starved"
    and "the attack is mis-wired" look identical from a bare ``KeyError``, and a
    Phase 3 author debugging that would reasonably conclude the harness was
    broken.

    Parameters
    ----------
    reason : str, optional
        Quoted in the :exc:`KeyError`. Defaults to the standing reason.

    Examples
    --------
    >>> from sih141.protocol.session import NO_RECIPIENT_LOGS
    >>> len(NO_RECIPIENT_LOGS), list(NO_RECIPIENT_LOGS)
    (0, [])
    >>> NO_RECIPIENT_LOGS.get(0, {})
    {}
    >>> try:
    ...     NO_RECIPIENT_LOGS[0]
    ... except KeyError as missing:
    ...     print(missing.args[0].split(":")[0])
    the signer seam was shown no recipient log
    """

    __slots__ = ("_reason",)

    def __init__(self, reason: str | None = None) -> None:
        self._reason = (
            "the signer seam was shown no recipient log: no adversary in the "
            "threat model holds one at signing time. Construct "
            "QDSSession(..., signer_sees_recipient_logs=True) to run the "
            "over-powered variant deliberately; the transcript flags it. A "
            "forging recipient belongs on the forwarder seam, which is handed "
            "his own RecipientView."
            if reason is None
            else reason
        )

    def __getitem__(self, key: int) -> Mapping[Party, RecipientRecord]:
        """Raise :exc:`KeyError` carrying the reason, for every key."""
        raise KeyError(self._reason)

    def __iter__(self) -> Iterator[int]:
        """Yield nothing: there is no log here to iterate over."""
        return iter(())

    def __len__(self) -> int:
        """int: ``0``, always."""
        return 0

    def __repr__(self) -> str:
        """Return a representation that names the class, not an empty dict."""
        return "WithheldRecords()"


NO_RECIPIENT_LOGS: Final[WithheldRecords] = WithheldRecords()
"""The default ``records`` argument to the :class:`Signer` seam.

A module-level singleton so that a test can assert *identity* -- "the session
passed this exact object" is a stronger and clearer claim than "the session
passed something empty". See :ref:`two-log-signer`.
"""


# --------------------------------------------------------------------------- #
# The channel monitor (see :ref:`phase3-seams`)
# --------------------------------------------------------------------------- #


class ChannelMonitor(Protocol):
    """Callable that summarises one check round's entanglement resource.

    Invoked as ``monitor(resource, context)`` once per check round per
    recipient, after the ``resource_factory`` produced the pair and before it is
    measured. It returns a mapping of extra diagnostics, which is carried in
    :attr:`ChannelSample.extra` and must survive :func:`json.dumps`: keys are
    strings and leaves are ``None``, :class:`bool`, :class:`int`, :class:`float`
    or :class:`str`, nested in lists and dictionaries as deep as it likes.
    NumPy scalars and arrays are converted rather than refused, since a monitor
    computing anything at all will produce them.

    It is an observer. Whatever it returns is recorded; the resource is
    delivered unchanged either way, so a monitor cannot become a channel attack
    by accident -- that seam is ``resource_factory``, one step earlier, and
    keeping them apart is what lets a Phase 4 detector be developed against the
    same runs a Phase 3 attack produced.

    Notes
    -----
    Called on check rounds **only** (:ref:`phase3-seams`). A monitor that wants
    to see every position is asking for the key rounds, which is the one thing
    sampling exists not to publish.
    """

    def __call__(
        self, resource: StateLike, context: ResourceContext
    ) -> Mapping[str, Any]:
        """Return extra diagnostics for this check round."""
        ...


def _as_json_value(value: Any, path: str) -> Any:
    """Coerce one monitor-supplied value to something :func:`json.dumps` accepts.

    Parameters
    ----------
    value : Any
        Whatever the monitor put in its mapping.
    path : str
        Dotted path to this value, quoted in the error message.

    Returns
    -------
    Any
        A JSON leaf, or a list/dict of them.

    Raises
    ------
    TypeError
        If the value is of a type JSON has no representation for, or if a
        mapping key is not a string.
    ValueError
        If a float is not finite: ``json.dumps`` writes ``NaN`` and ``Infinity``
        by default, which are not JSON and which no other reader will accept, so
        a transcript carrying one is not the portable record this type promises.

    Notes
    -----
    The conversion is deliberate rather than defensive. A monitor computing a
    fidelity gets a :class:`numpy.float64`, which
    :func:`json.dumps` refuses; refusing it here as well would make the seam
    unusable for its purpose, and coercing it at write time would hide the
    failure until Phase 6 served the transcript.
    """
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, (int, np.integer)):
        return int(value)
    if isinstance(value, (float, np.floating)):
        number = float(value)
        if not np.isfinite(number):
            raise ValueError(
                f"channel_monitor returned a non-finite number at {path}: "
                f"{value!r}. json.dumps would write it as NaN or Infinity, "
                f"which is not JSON and which no other reader accepts, so the "
                f"transcript would stop being portable. Report a sentinel "
                f"(None) or a flag instead."
            )
        return number
    if isinstance(value, np.bool_):
        return bool(value)
    if isinstance(value, (complex, np.complexfloating)):
        raise TypeError(
            f"channel_monitor returned a complex number at {path}: {value!r}. "
            f"JSON has no complex type, and picking a convention here -- a "
            f"two-element list? an object with re and im? -- would make every "
            f"reader guess. Publish the parts explicitly, "
            f"[float(z.real), float(z.imag)], or the modulus, and say in the "
            f"key which it is. A whole density matrix comes out as "
            f"rho.real.tolist() and rho.imag.tolist() under two keys."
        )
    if isinstance(value, np.ndarray):
        return _as_json_value(value.tolist(), path)
    if isinstance(value, Mapping):
        converted: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(
                    f"channel_monitor returned a non-string key at {path}: "
                    f"{key!r} of type {type(key).__name__}. JSON object keys "
                    f"are strings, and a transcript that needed an encoder "
                    f"would not round-trip."
                )
            converted[key] = _as_json_value(item, f"{path}.{key}")
        return converted
    if isinstance(value, (list, tuple)):
        return [
            _as_json_value(item, f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    raise TypeError(
        f"channel_monitor returned {type(value).__name__} at {path}, which has "
        f"no JSON representation. A ChannelSample is carried in the transcript "
        f"and the transcript must survive json.dumps end to end; summarise the "
        f"object into numbers or strings in the monitor itself, which is the "
        f"one place that knows what the summary should be."
    )


def _as_pair(
    resource: StateLike, context: ResourceContext
) -> DensityMatrix:
    """Coerce one hop's resource and refuse anything that is not a pair.

    Parameters
    ----------
    resource : StateLike
        What the ``resource_factory`` produced for this hop, in either
        representation (D1).
    context : ResourceContext
        The hop, quoted in the error message.

    Returns
    -------
    qiskit.quantum_info.DensityMatrix
        The resource as a two-qubit density matrix.

    Raises
    ------
    ValueError
        If it is not a two-qubit state.
    """
    density = as_density(resource)
    if density.num_qubits != 2:
        raise ValueError(
            f"a check round measures both halves of an entanglement "
            f"resource, so the resource must be a two-qubit state; got "
            f"{density.num_qubits} qubit(s) for {context.party.value} at "
            f"position {context.position} of message bit "
            f"{context.message_bit}. The resource_factory is what produced "
            f"it."
        )
    return density


def _call_monitor(
    monitor: ChannelMonitor | None,
    density: DensityMatrix,
    context: ResourceContext,
) -> Mapping[str, Any]:
    """Put one hop's resource past the channel-monitor seam.

    Parameters
    ----------
    monitor : ChannelMonitor or None
        The seam. ``None`` returns an empty mapping without touching the state,
        which is what keeps an unmonitored run free of the copy below.
    density : qiskit.quantum_info.DensityMatrix
        The resource, already checked to be a pair by :func:`_as_pair`.
    context : ResourceContext
        The hop.

    Returns
    -------
    mapping
        Whatever the seam returned, unvalidated as to its *contents* --
        :class:`ChannelSample` coerces those to JSON leaves and is the one
        place that has to.

    Raises
    ------
    TypeError
        If ``monitor`` is not callable, or did not return a mapping.
    """
    if monitor is None:
        return {}
    if not callable(monitor):
        raise TypeError(
            f"channel_monitor must be a callable "
            f"monitor(resource, context), got {type(monitor).__name__}."
        )
    # A COPY, and this is the line that makes "an observer cannot become a
    # channel attack" true rather than merely intended. The seam is handed the
    # state the channel delivered; a qiskit state exposes its array, so handing
    # over the object itself would let a monitor edit the pair between the
    # factory that produced it and the measurement that consumes it -- a
    # channel attack wearing an observer's name, and one that would not show up
    # in the transcript as a channel attack at all. Four by four, once per hop.
    returned = monitor(
        DensityMatrix(np.array(density.data, copy=True)), context
    )
    if not isinstance(returned, Mapping):
        raise TypeError(
            f"channel_monitor must return a mapping of JSON-safe "
            f"diagnostics, got {type(returned).__name__} for "
            f"{context.party.value} at position {context.position}. "
            f"Return an empty mapping to record nothing beyond the "
            f"built-in summary."
        )
    return returned


@dataclass(frozen=True)
class ChannelSample:
    """What one check round's entanglement resource was, before it was measured.

    The channel-monitor seam's output, one per check round per recipient per
    message bit, carried in :attr:`SessionTranscript.channel`. It is the
    *resource* side of a check round; the :class:`~sih141.protocol.checkrounds.CheckLog`
    carried beside it is the *outcome* side, and the two are joined by
    ``(party, message_bit, position)``.

    Every field is a plain number, a string or JSON of them: no quantum state
    survives into a transcript, here or anywhere else in this module.

    Attributes
    ----------
    party : Party
        The recipient whose link this pair was drawn for.
    message_bit : int
        Which of the two distributions the round belongs to.
    position : int
        The key index the round occupied, in the **unsifted** ``0 .. L-1``
        numbering -- the same numbering
        :attr:`~sih141.protocol.checkrounds.CheckRoundPlan.positions` uses,
        which is what makes a sample joinable to the plan and to the log. It is
        *not* an index into the sifted record, and cannot be: a check position
        is precisely one the record does not contain.
    role : CheckRole
        :attr:`~sih141.protocol.checkrounds.CheckRole.QBER` or
        :attr:`~sih141.protocol.checkrounds.CheckRole.CHSH`, i.e. which arm the
        round was spent on.
    fidelity : float
        :math:`\\langle\\Phi^{+}|\\rho|\\Phi^{+}\\rangle` for the resource
        actually delivered, in the squared convention of
        :func:`sih141.core.states.fidelity`. ``1.0`` on an ideal pair.
    purity : float
        :math:`\\mathrm{Tr}(\\rho^2)`, in ``[0.25, 1]`` for two qubits. It
        separates a *mixing* attack from a *unitary* one: a rotated pair is
        still pure and still wrong.
    concurrence : float
        Entanglement of the pair, ``1.0`` for a Bell state and ``0.0`` for
        anything separable. A resource an eavesdropper has entangled himself
        with arrives here as a mixed, less entangled pair, which is what the
        CHSH arm is testing for on the same round.
    alice_purity : float
        :math:`\\mathrm{Tr}(\\rho_A^2)` for the half Alice keeps -- resource
        qubit ``0``, the convention
        :func:`~sih141.protocol.checkrounds.observe_qber_round` measures on.
    recipient_purity : float
        The same for the half that travels to the recipient, resource qubit
        ``1``. **The pair of them is the wing-resolved signal, and the reason
        the two numbers are kept apart rather than summarised.** Both are
        ``0.5`` on a clean :math:`|\\Phi^{+}\\rangle`, because each half of a
        maximally entangled pair is maximally mixed on its own; a channel that
        damps only the leg in flight raises this one and leaves the other where
        it was, and no global quantity says which end was touched.
    extra : mapping, optional
        Whatever the ``channel_monitor`` seam returned, JSON-safe. Empty when
        no monitor was given. A sample carrying a non-empty ``extra`` is not
        hashable, which is deliberate: it is a record to be read, not a key.

    See Also
    --------
    sih141.protocol.checkrounds.CheckLog : The outcomes for the same rounds.

    Examples
    --------
    >>> from sih141.core.states import BellState, bell_state
    >>> from sih141.protocol.checkrounds import QberRound
    >>> from sih141.protocol.distribute import ResourceContext
    >>> from sih141.protocol.params import Party
    >>> from sih141.protocol.session import ChannelSample
    >>> context = ResourceContext(party=Party.BOB, message_bit=1, position=7)
    >>> sample = ChannelSample.of(
    ...     bell_state(BellState.PHI_PLUS), context, QberRound(7, "Z")
    ... )
    >>> sample.role, sample.fidelity, sample.purity
    (<CheckRole.QBER: 'qber'>, 1.0, 1.0)
    >>> round(sample.concurrence, 12)     # 1, to the last few bits of a 4x4
    1.0
    >>> sample.is_ideal
    True
    >>> ChannelSample.from_dict(sample.to_dict()) == sample
    True

    Each half of a maximally entangled pair is maximally mixed on its own, so
    both wings sit at ``0.5`` and neither end looks disturbed:

    >>> round(sample.alice_purity, 9), round(sample.recipient_purity, 9)
    (0.5, 0.5)
    >>> sample.wings_agree
    True

    A pair whose travelling half was left pure is not entangled at all, and the
    two wings say which end it happened at (D2):

    >>> import numpy as np
    >>> from qiskit.quantum_info import DensityMatrix, Statevector
    >>> split = DensityMatrix(Statevector([1, 0])).tensor(
    ...     DensityMatrix(np.eye(2) / 2)
    ... )
    >>> broken = ChannelSample.of(split, context, QberRound(7, "Z"))
    >>> round(broken.alice_purity, 9), round(broken.recipient_purity, 9)
    (0.5, 1.0)
    >>> broken.concurrence, broken.wings_agree
    (0.0, False)
    """

    party: Party
    message_bit: int
    position: int
    role: CheckRole
    fidelity: float
    purity: float
    concurrence: float
    alice_purity: float
    recipient_purity: float
    extra: Mapping[str, Any] = MappingProxyType({})

    def __post_init__(self) -> None:
        """Coerce the tags and check the three summaries are real numbers.

        Raises
        ------
        TypeError
            If ``extra`` is not a mapping, or holds something JSON cannot carry.
        ValueError
            If ``party`` is Alice or names no party, if ``message_bit`` is not
            ``0``/``1``, if ``position`` is negative, or if any of the three
            summaries is outside its range.
        """
        resolved = _as_party(self.party)
        if resolved is Party.ALICE:
            raise ValueError(
                "a ChannelSample describes one link, and Alice is the common "
                "endpoint of both: tag it with the recipient whose pair this "
                "was, Party.BOB or Party.CHARLIE."
            )
        object.__setattr__(self, "party", resolved)
        object.__setattr__(
            self, "message_bit", _as_message_bit(self.message_bit)
        )
        if not isinstance(self.position, (int, np.integer)) or isinstance(
            self.position, bool
        ):
            raise TypeError(
                f"position must be an integer key index, got "
                f"{type(self.position).__name__}."
            )
        object.__setattr__(self, "position", int(self.position))
        if self.position < 0:
            raise ValueError(
                f"position must be a key index in 0 .. L-1, got "
                f"{self.position}."
            )
        if not isinstance(self.role, CheckRole):
            object.__setattr__(
                self, "role", CheckRole(str(self.role).strip().lower())
            )
        for name, value, low, high in (
            ("fidelity", self.fidelity, 0.0, 1.0),
            ("purity", self.purity, 0.0, 1.0),
            ("concurrence", self.concurrence, 0.0, 1.0),
            # A single qubit's purity floors at 1/2, not at 0; the wider bound
            # is checked here because the tighter one is a claim about the
            # partial trace rather than about the field.
            ("alice_purity", self.alice_purity, 0.0, 1.0),
            ("recipient_purity", self.recipient_purity, 0.0, 1.0),
        ):
            try:
                number = float(value)
            except (TypeError, ValueError):
                raise TypeError(
                    f"{name} must be a real number, got "
                    f"{type(value).__name__} ({value!r}). A ChannelSample "
                    f"carries the summary of a two-qubit state, not a label "
                    f"for it."
                ) from None
            if not np.isfinite(number) or not low <= number <= high:
                raise ValueError(
                    f"{name} must be a finite number in [{low}, {high}], got "
                    f"{value!r}. It is a property of a physical two-qubit "
                    f"state; a value outside the range means the sample was "
                    f"built from something that is not one."
                )
            object.__setattr__(self, name, number)
        if not isinstance(self.extra, Mapping):
            raise TypeError(
                f"extra must be a mapping of the channel_monitor's extra "
                f"diagnostics, got {type(self.extra).__name__}. A monitor that "
                f"has nothing to add should return an empty mapping."
            )
        object.__setattr__(
            self,
            "extra",
            MappingProxyType(dict(_as_json_value(self.extra, "extra"))),
        )

    # -- construction ------------------------------------------------------- #

    @classmethod
    def of(
        cls,
        resource: StateLike,
        context: ResourceContext,
        scheduled: QberRound | ChshRound,
        *,
        monitor: ChannelMonitor | None = None,
        extra: Mapping[str, Any] | None = None,
    ) -> ChannelSample:
        """Summarise the resource one check round was handed.

        Parameters
        ----------
        resource : StateLike
            The two-qubit pair the ``resource_factory`` produced for this hop,
            in either representation (D1).
        context : ResourceContext
            The hop: party, message bit and position.
        scheduled : QberRound or ChshRound
            The planned round, which supplies :attr:`role` and is checked to sit
            at ``context.position``.
        monitor : ChannelMonitor or None, optional
            Keyword-only. The seam, invoked here; ``None`` records the built-in
            summary alone.
        extra : mapping or None, optional
            Keyword-only. A monitor's output already collected by the caller,
            for the case where the seam must be invoked somewhere this method
            cannot see -- which is every position, not only the check ones, so
            that being called stops being the signal it was
            (:class:`_ChannelTap`). Mutually exclusive with ``monitor``.

        Returns
        -------
        ChannelSample

        Raises
        ------
        ValueError
            If ``resource`` is not a two-qubit state, if ``scheduled`` is for
            another position, or if both ``monitor`` and ``extra`` are given.
        TypeError
            If ``monitor`` is not callable, or returned something that is not a
            JSON-safe mapping.
        """
        if scheduled.position != context.position:
            raise ValueError(
                f"the scheduled check round is at position "
                f"{scheduled.position} but the hop being summarised is at "
                f"{context.position}. The two come from one plan and one loop; "
                f"a mismatch would file this pair's diagnostics against another "
                f"position's outcomes."
            )
        if monitor is not None and extra is not None:
            raise ValueError(
                "pass either monitor= to invoke the seam here or extra= to "
                "record what it already returned, not both: two calls for one "
                "hop would double every count a monitor keeps and leave the "
                "sample carrying the second one's answer."
            )
        density = _as_pair(resource, context)
        if extra is None:
            extra = _call_monitor(monitor, density, context)
        reference = bell_state(BellState.PHI_PLUS)
        return cls(
            party=context.party,
            message_bit=context.message_bit,
            position=context.position,
            role=scheduled.role,
            fidelity=fidelity(density, reference),
            purity=purity(density),
            concurrence=concurrence(density),
            # Which half is whose comes from :mod:`sih141.protocol.checkrounds`
            # rather than from a literal here, so that the two modules cannot
            # disagree about it -- reading the pair the wrong way round would
            # attribute a one-sided attack to the wrong party with nothing
            # failing (D2).
            alice_purity=purity(partial_trace(density, [_RECIPIENT_QUBIT])),
            recipient_purity=purity(partial_trace(density, [_ALICE_QUBIT])),
            extra=extra,
        )

    # -- derived views ------------------------------------------------------ #

    @property
    def is_ideal(self) -> bool:
        """bool: Whether this pair was the clean :math:`|\\Phi^{+}\\rangle`.

        All three summaries at ``1.0``, to within the tolerance floating-point
        arithmetic on a 4x4 matrix leaves. A convenience for "did the channel
        seam do anything at all here", not a detection statistic: one round says
        nothing about a channel, which is why
        :mod:`sih141.protocol.checkrounds` estimates from a sample and reports
        an interval.
        """
        return (
            abs(self.fidelity - 1.0) <= 1e-9
            and abs(self.purity - 1.0) <= 1e-9
            and abs(self.concurrence - 1.0) <= 1e-9
        )

    @property
    def wings_agree(self) -> bool:
        """bool: Whether the two halves are equally disturbed.

        ``alice_purity == recipient_purity`` to floating-point tolerance. Every
        symmetric channel model in this package leaves it ``True`` -- including
        a Werner pair, which mixes both halves equally -- so ``False`` is the
        signature of something that acted on one leg **and changed only that
        leg's marginal**: damping, or replacement of one half by another state.
        The worked example this property was written for is a split product
        state.

        **It is not an eavesdropper detector, and Phase 3 measured that it is
        not.** No trace-preserving map on one half of a maximally entangled pair
        can change only that half's marginal -- the reduced state of either half
        of a Bell pair is already maximally mixed, and a channel acting on one
        wing leaves it maximally mixed. So all three of
        :mod:`sih141.attacks.channel`'s adversaries act on exactly one leg and
        every one of them leaves ``wings_agree`` ``True`` on every round: a
        per-hop depolariser, an intercept-resend, and an eavesdropper who keeps
        a share of the state. Zero detection power against that whole family. A
        Phase 4 detector that reads this property as "somebody is on the wire"
        will report a clean link under all three; the statistics that do see
        them are :attr:`fidelity` and :attr:`concurrence` (both attacks and the
        twirl), :attr:`purity` (a kept share, and nothing else), and above all
        the per-link check-round QBER of
        :func:`~sih141.protocol.checkrounds.estimate_qber`.

        Like :attr:`is_ideal`, a convenience for reading one round and not a
        detection statistic: one pair says nothing about a channel, and the
        interval that does is :mod:`sih141.protocol.checkrounds`' job.
        """
        return abs(self.alice_purity - self.recipient_purity) <= 1e-9

    # -- serialisation ------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the sample.

        Returns
        -------
        dict
            Keys ``"party"``, ``"message_bit"``, ``"position"``, ``"role"``,
            ``"fidelity"``, ``"purity"``, ``"concurrence"``,
            ``"alice_purity"``, ``"recipient_purity"`` and ``"extra"``.
            :class:`~sih141.protocol.params.Party` and
            :class:`~sih141.protocol.checkrounds.CheckRole` are
            :class:`enum.StrEnum` members, which *are* strings.
        """
        return {
            "party": self.party,
            "message_bit": self.message_bit,
            "position": self.position,
            "role": self.role,
            "fidelity": self.fidelity,
            "purity": self.purity,
            "concurrence": self.concurrence,
            "alice_purity": self.alice_purity,
            "recipient_purity": self.recipient_purity,
            "extra": dict(self.extra),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ChannelSample:
        """Rebuild a sample from :meth:`to_dict` output.

        Parameters
        ----------
        data : mapping
            Must carry every key :meth:`to_dict` writes except ``"extra"``,
            which defaults to empty -- a sample written before a monitor was
            attached had nothing extra, and that is the truth about it.

        Returns
        -------
        ChannelSample

        Raises
        ------
        KeyError
            If a required field is missing.
        """
        return cls(
            party=data["party"],
            message_bit=data["message_bit"],
            position=data["position"],
            role=data["role"],
            fidelity=data["fidelity"],
            purity=data["purity"],
            concurrence=data["concurrence"],
            alice_purity=data["alice_purity"],
            recipient_purity=data["recipient_purity"],
            extra=data.get("extra", {}),
        )


class _ChannelTap:
    """The ``resource_factory`` with a check-round summary taken on the way past.

    Wraps the caller's factory (or :func:`~sih141.protocol.distribute.ideal_resource`
    when there is none) and is what :meth:`QDSSession.distribute` actually hands
    the distributor on a checked run. For every hop it calls the underlying
    factory exactly as :mod:`sih141.protocol.distribute` would, then puts the
    resource past the ``channel_monitor`` -- **also on every hop** -- and
    *then*, only at a position this link's plan designates a check round,
    records a :class:`ChannelSample`.

    Calling the monitor everywhere and recording almost nowhere is the whole
    design, and the asymmetry is the point. *Being called* is a signal: a
    monitor invoked at check positions only publishes the check set to whoever
    holds the seam, in one pass, with no statistics and no inference -- the
    declared channel-side adversary holds this seam and the two in
    :mod:`sih141.protocol.distribute` together, so a call pattern that differs
    between the branches is a call pattern that hands the check set over. What
    must stay true is the *other* half of the original argument: nothing is
    ever **recorded** at a key position, because a per-position statement about
    the rounds the key is made of would stop the sample being a sample. So the
    seam sees everything and the transcript sees only the check rounds, and
    :func:`_check_sample_against` re-checks that on the way back in from JSON.

    The order matters and is the reason this is a wrapper rather than a hook
    inside the distribution loop. The underlying factory is called identically
    at every position, before anything is recorded and with a context that says
    nothing about the branch, so the invariant that an adversary standing at the
    channel cannot tell a watched round from an unwatched one
    (:ref:`sih141.protocol.distribute <check-round-lockstep>`) is untouched: the
    tap is downstream of the only thing the adversary can see.

    One tap serves every link of one message bit, and the plan deals its
    reserved rounds between them
    (:ref:`sih141.protocol.checkrounds <check-round-links>`), so which rounds
    are recorded is looked up per :attr:`~ResourceContext.party` -- indexed once
    per link, on that link's first hop.

    Parameters
    ----------
    factory : ResourceFactory or None
        The session's channel seam.
    plan : CheckRoundPlan
        The plan for this message bit, indexed per link on first use.
    monitor : ChannelMonitor or None
        The extra-diagnostics seam.
    sink : list of ChannelSample
        Where samples are appended, in call order. The session owns it.
    """

    __slots__ = (
        "_factory",
        "_wants_context",
        "_plan",
        "_planned",
        "_monitor",
        "_sink",
    )

    def __init__(
        self,
        factory: ResourceFactory | None,
        *,
        plan: CheckRoundPlan,
        monitor: ChannelMonitor | None,
        sink: list[ChannelSample],
    ) -> None:
        self._factory, self._wants_context = _resolve_factory(factory)
        self._plan = plan
        self._planned: dict[Party, dict[int, QberRound | ChshRound]] = {}
        self._monitor = monitor
        self._sink = sink

    def _rounds_for(self, party: Party) -> dict[int, QberRound | ChshRound]:
        """Return this link's planned rounds, indexed once per link.

        Parameters
        ----------
        party : Party
            The recipient whose link the hop belongs to.

        Returns
        -------
        dict
            Position to planned round, for the rounds this link measures.
        """
        rounds = self._planned.get(party)
        if rounds is None:
            rounds = self._plan.rounds_by_position(party)
            self._planned[party] = rounds
        return rounds

    def __call__(self, context: ResourceContext) -> StateLike:
        """Draw one hop's resource, monitor it, and record it if it is watched."""
        resource = _draw_resource(self._factory, self._wants_context, context)
        # Every hop, so that the seam cannot read the plan off its own call
        # sequence. Guarded rather than folded into the call, so that a run
        # with no monitor neither coerces the state nor validates it here: the
        # pair check would otherwise fire at position 0 of an unmonitored run
        # instead of where it used to, and an honest run's cost would grow for
        # a seam it does not have.
        extra: Mapping[str, Any] = {}
        if self._monitor is not None:
            extra = _call_monitor(
                self._monitor, _as_pair(resource, context), context
            )
        scheduled = self._rounds_for(context.party).get(context.position)
        if scheduled is not None:
            self._sink.append(
                ChannelSample.of(resource, context, scheduled, extra=extra)
            )
        return resource


# --------------------------------------------------------------------------- #
# The callable seams (see :ref:`phase3-seams`)
# --------------------------------------------------------------------------- #


class Distributor(Protocol):
    """Callable that runs Phase A for one message bit.

    :func:`~sih141.protocol.distribute.distribute_public_key_with_checks` is the
    honest implementation and the default. A Phase 3 replacement stands between
    Alice and the recipients and may return any records it likes; the session
    checks the shape of the result (see :meth:`QDSSession.distribute`) but not
    its contents, because "the contents are wrong" is exactly what verification
    is for.

    **Two return shapes are accepted**, and a seam may use either. A mapping of
    party to :class:`~sih141.protocol.records.RecipientRecord` is the historical
    one and stays valid for ever; a mapping of party to
    :class:`~sih141.protocol.distribute.RecipientDistribution` additionally
    carries the check-round log, which is the only way a run's channel
    statistics reach the transcript. A seam written before check rounds existed
    therefore keeps working and simply publishes no statistics -- which is the
    truth about it.

    The ``rng`` it is passed is the session's **Alice-side** stream. Cloning its
    state, rewinding it or rebuilding its seed sequence says nothing about the
    symmetrisation coins, which are drawn from a stream derived under a
    different label and never shown to this seam (:ref:`two-streams`). An
    implementation that wants randomness of its own should still close over its
    own generator, so that what it draws does not move Alice's stream.

    Notes
    -----
    ``check_plan`` and ``payload_map`` are passed **only when they are in
    force** -- the first when the parameter set reserves check rounds, the
    second when a payload seam was given -- so a two-keyword seam written before
    either existed is called exactly as it always was. A seam that wants them
    must accept them; one that accepts ``**kwargs`` gets them for free.
    """

    def __call__(
        self,
        key: PrivateKey,
        params: ProtocolParams,
        *,
        parties: Sequence[Party | str] = VERIFIERS,
        resource_factory: ResourceFactory | None = None,
        rng: np.random.Generator | None = None,
        check_plan: CheckRoundPlan | None = None,
        payload_map: PayloadMap | None = None,
    ) -> Mapping[Party, RecipientRecord | RecipientDistribution]:
        """Distribute ``key`` and return one record per party."""
        ...


class Signer(Protocol):
    """Callable that runs Phase B and produces the declaration to be verified.

    :func:`honest_signer` is the default. The first three parameters are
    everything a repudiating Alice holds at signing time (:ref:`threat-model`),
    which is what this seam is for; an adversarial signer uses them differently
    from an honest one, and that is how "who is cheating" is expressed without a
    flag.

    ``records`` is :data:`NO_RECIPIENT_LOGS` unless the session was built with
    ``signer_sees_recipient_logs=True``, in which case it is both recipients'
    raw logs -- more than any single adversary in the model holds, deliberately
    reachable, and flagged in the transcript. See :ref:`two-log-signer`, and
    :ref:`forger-route` for where a forging recipient actually belongs.
    """

    def __call__(
        self,
        message_bit: int,
        keys: tuple[PrivateKey, PrivateKey],
        params: ProtocolParams,
        *,
        records: Mapping[int, Mapping[Party, RecipientRecord]],
    ) -> Signature:
        """Return the signature declared for ``message_bit``."""
        ...


def honest_signer(
    message_bit: int,
    keys: tuple[PrivateKey, PrivateKey],
    params: ProtocolParams,
    *,
    records: Mapping[int, Mapping[Party, RecipientRecord]],
) -> Signature:
    """Declare exactly the key whose states were distributed. The default signer.

    A thin :class:`Signer`-shaped adapter over
    :func:`sih141.protocol.signature.sign`. It exists as a named function rather
    than a lambda so that Phase 3 can wrap it, and so that a test can assert the
    default really is the honest one.

    Parameters
    ----------
    message_bit : int
        ``0`` or ``1``, the bit being signed.
    keys : tuple of PrivateKey
        ``(k_0, k_1)``, Alice's committed pair. ``keys[message_bit]`` is
        declared verbatim.
    params : ProtocolParams
        Checked against the selected key, so a key from another parameter set is
        refused at signing time rather than as an unexplained rejection at both
        verifiers.
    records : mapping
        Keyword-only. **Ignored**, deliberately: the recipients' logs are Bob's
        and Charlie's private evidence, not Alice's, and an honest Alice signs
        without them. On a default session this is :data:`NO_RECIPIENT_LOGS`
        and there is nothing in it to ignore; the parameter is part of the
        :class:`Signer` shape because the over-powered opt-in fills it in (see
        :ref:`two-log-signer`).

    Returns
    -------
    Signature
        ``sign(message_bit, keys, params)``.

    Raises
    ------
    ValueError
        If ``message_bit`` is not ``0``/``1``, or ``keys`` is not the ordered
        pair ``(k_0, k_1)``.
    TypeError
        As :func:`sih141.protocol.signature.sign`.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.keys import generate_key_pair
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import honest_signer
    >>> params = ProtocolParams(key_length=9)
    >>> keys = generate_key_pair(params, rng=np.random.default_rng(5))
    >>> honest_signer(1, keys, params, records={}).declared_key is keys[1]
    True
    """
    del records  # An honest Alice holds no recipient's measurement log.
    return sign(message_bit, keys, params)


class Forwarder(Protocol):
    """Callable that carries the declaration from Bob to Charlie.

    :func:`honest_forwarder` is the default and is the identity. A Phase 3
    replacement models Bob altering what he passes on, or an adversary sitting
    on the forwarding link; whatever it returns is what Charlie scores, and the
    transcript records both declarations separately.

    **This is where a forging recipient stands** (:ref:`forger-route`), so the
    seam may ask for what that adversary holds: a forwarder that declares a
    **required** keyword-only ``view`` parameter is handed Bob's
    :class:`~sih141.protocol.records.RecipientView` -- his raw log, his
    post-exchange log and his own matched count, with no way to reach Charlie's.
    The session decides once, at construction, by inspecting the callable, so a
    forwarder taking ``(signature, params)`` alone is called with two arguments
    exactly as before and nothing older breaks.

    *Required*, on the same reasoning that makes
    :data:`~sih141.protocol.distribute.ResourceFactory` treat a defaulted
    parameter as "does not want one": a callable that can be invoked with two
    arguments is invoked with two. ``view=None`` is how :func:`honest_forwarder`
    matches this shape while declining the evidence, and an attack that wants
    the view writes ``*, view`` with no default.

    Ask for the view only if the attack needs it. It is built on demand, and
    building it validates the run's logs, so a session wired with a distributor
    that returns something a :class:`~sih141.protocol.records.RecipientView`
    refuses to describe still works for every forwarder that does not ask.
    """

    def __call__(
        self,
        signature: Signature,
        params: ProtocolParams,
        *,
        view: RecipientView | None = None,
    ) -> Signature:
        """Return the declaration Charlie will be given."""
        ...


def honest_forwarder(
    signature: Signature,
    params: ProtocolParams,
    *,
    view: RecipientView | None = None,
) -> Signature:
    """Forward the declaration unchanged. The default forwarder.

    Bob forwards the declaration, never his own evidence -- which is why an
    honest Bob cannot help a signature along, and why a dishonest one cannot
    either without altering the declaration, which is exactly what this seam
    makes visible.

    Parameters
    ----------
    signature : Signature
        What Bob received and scored.
    params : ProtocolParams
        The parameter set. **Ignored** by the honest forwarder; present because
        a replacement that rebuilds a declaration needs the alphabet and the
        key length to build a valid one.
    view : RecipientView or None, optional
        Keyword-only, and **defaulted, which is how this function declines it**.
        An honest hop passes on what it was given and does not consult its own
        evidence to do so, and the session only builds a view for a forwarder
        that *requires* one. Declared anyway so that the honest default has the
        full :class:`Forwarder` shape and a replacement can be written by
        copying its signature.

    Returns
    -------
    Signature
        ``signature`` itself, unchanged and identical by object identity, so a
        test can assert the honest path really did nothing.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.keys import generate_key_pair
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import honest_forwarder
    >>> from sih141.protocol.signature import sign
    >>> params = ProtocolParams(key_length=9)
    >>> keys = generate_key_pair(params, rng=np.random.default_rng(5))
    >>> declaration = sign(0, keys, params)
    >>> honest_forwarder(declaration, params) is declaration
    True
    """
    del params, view  # An honest hop needs nothing but the declaration itself.
    return signature


# --------------------------------------------------------------------------- #
# The transcript
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SessionTranscript:
    """Everything one run produced, frozen and JSON-serialisable end to end.

    The hand-off object for the rest of the project: Phase 4 computes detection
    statistics from it, Phase 5 aggregates many of them, and Phase 6 renders
    one. It therefore contains no quantum state, no generator and no callable --
    only the parameter set, the declaration, the classical logs and the
    verdicts. :meth:`to_dict` output passes to :func:`json.dumps` unchanged, and
    :meth:`from_dict` round-trips it back to an equal object.

    Being a frozen dataclass over frozen fields, two transcripts compare equal
    exactly when the two runs were identical, which is what makes "the same seed
    reproduces the run" a one-line assertion.

    Attributes
    ----------
    params : ProtocolParams
        The parameter set the run executed under, thresholds included.
    message_bit : int
        The bit that was signed.
    signature : Signature
        The declaration **Bob** scored. On an attacked run this is whatever the
        :class:`Signer` seam produced, which need not be a key Alice ever
        distributed -- that is the point of a forgery.
    records : tuple of RecipientRecord
        All ``len(MESSAGE_BITS) * 2`` logs from Phase A, in distribution order:
        bit 0 for Bob then Charlie, then bit 1 for Bob then Charlie. Each one
        carries its own party, message bit and
        :attr:`~sih141.protocol.records.RecipientRecord.symmetrised` flag, so
        the flat tuple is unambiguous and survives JSON without integer
        dictionary keys.
    results : tuple of VerificationResult
        The verdicts reached, in the order they were reached -- Bob's first,
        then Charlie's after the transfer. May be shorter than two if a run was
        abandoned part-way, or if a verifier reached no verdict at all (see
        ``aborts``).
    aborts : tuple of VerificationAbort, optional
        The verifiers who reached **no verdict**, because the declaration left
        them a matched set below
        :func:`~sih141.protocol.verify.minimum_matched_count`. Empty on every
        healthy run. A separate field from ``results``, and a separate type,
        because a refusal to score is neither an acceptance nor a rejection: a
        plumbing failure counted as a rejection would show up in a Phase 5 table
        as a forgery detection that never happened. A party appears in exactly
        one of the two, never both.
    forwarded_signature : Signature or None, optional
        The declaration **Charlie** scored, when it differs from
        :attr:`signature`. ``None`` on every honest run, where Bob forwards what
        he received unchanged. Carried because a run in which the two verifiers
        scored different declarations is otherwise unrepresentable, and a
        transcript that recorded only Bob's would attribute Charlie's verdict to
        a declaration he never saw -- which a Phase 4 statistic would read as a
        clean run.
    run_id : str or None, optional
        An identifier for the replay ledger, supplied by whoever owns the
        ledger's namespace. Carried and otherwise unused. ``None`` by default:
        the transcript deliberately generates nothing, because a random
        identifier would break seed reproducibility and a seed-derived one would
        repeat exactly when a replay does.
    pooled : PooledMatchedCounts or None, optional
        What the recipients learned from each other in Phase C'
        (:mod:`sih141.protocol.tally`): the two matched counts, their total, and
        the two floors the run was scored under. ``None`` marks a run whose
        recipients did **not** compare counts -- the pre-pooled variant, which
        :func:`~sih141.protocol.tally.no_count_exchange` produces and which has
        no unconditional non-repudiation guarantee below ``1/2``. A separate
        field from ``results`` and ``aborts`` because it is neither: it is the
        evidence base all three of them were decided on, and a Phase 5 table
        that could not see it could not tell an aimed-low declaration from an
        unlucky one.
    check_logs : tuple of CheckLog, optional
        The **published** check-round observations, one per recipient per
        message bit, on a run with check rounds; empty otherwise, which is the
        honest representation of "this run published no channel statistics".
        Publishing the raw observations rather than a reported rate is what
        makes the estimate auditable: hand one to
        :func:`~sih141.protocol.checkrounds.estimate_qber` or
        :func:`~sih141.protocol.checkrounds.estimate_chsh` and the interval
        comes out again. Bob's and Charlie's are separate samples of two
        different links and must stay separate -- pooling them reports the
        average of two channels and detects neither, which is the exact shape of
        a one-sided attack.
    channel : tuple of ChannelSample, optional
        One summary of the entanglement resource per check round per recipient
        per message bit, in the order the hops happened. Empty on a run without
        check rounds. **Only check positions appear here, ever**; a sample at a
        position the matching ``check_logs`` entry did not record is refused by
        :meth:`from_dict`, because "the channel was watched at every position"
        and "the channel was sampled" are different protocols and only the
        second one is this one.
    signer_saw_recipient_logs : bool, optional
        ``True`` on a run whose :class:`Signer` seam was shown both recipients'
        raw logs -- more than any single adversary in the threat model holds
        (:ref:`two-log-signer`). ``False`` by default and on every honest run.
        Carried for exactly the reason :attr:`symmetrised` is: an insecure-arm
        measurement must be unmistakable in the record it leaves, so that no
        Phase 5 table can quote it as if it described the shipped scheme.
    count_exchange_timing : str, optional
        Which declaration Phase C' counted against:
        :data:`COUNTS_BEFORE_FORWARDING` (the default and the shipped ordering)
        or :data:`COUNTS_AFTER_FORWARDING`. Carried for the same reason as the
        two flags above and with more urgency than either, because the two
        orderings give *different answers to the same attack*: a declaration
        substituted on the hop is refused under the first and scored under the
        second, so a table that pooled runs from both would be averaging a
        forgery rate with a denial-of-service rate. Phase 3 measured
        ``0/50`` forgeries scored under the first ordering and ``96/300``
        accepted under the second, against one analytic prediction of
        ``0.345566``; only the second is a measurement of the prediction.
        (``105/300`` appeared here in an earlier revision. It came from a
        working-note draft, not from the shipped code, which measures
        ``96/300 = 0.3200`` at ``z = -0.93`` -- the figure ``docs/PHASE3.md``
        and ``README.md`` carry, and the one an independent re-measurement
        reproduced count for count.)
    spent_rounds : tuple of tuple, optional
        What each verifier's replay ledger holds at the end of the run, as
        ``(party, session_id, message_bit)`` triples sorted for reproducibility.
        Empty on a run in which neither verifier reached a verdict. Present
        because a Phase 4 detector asked for it and could not get it: the
        ledger is an object the verifier holds, and "this round was spent by
        this verifier" is otherwise unreachable from the transcript, which made
        every replay statistic unanswerable after the fact
        (:ref:`sih141.protocol.verify <replay>`).
    replay_refusals : tuple of tuple, optional
        ``(party, count)`` for each verifier who was asked to decide a round he
        had already decided, sorted. Empty on every honest run, because an
        honest run asks each verifier once. Counted rather than filed in
        ``aborts`` for the reason :meth:`QDSSession.verify` gives: recording the
        refusal as that verifier's outcome would let a replayed presentation
        *delete* the acceptance that spent the round, which is a larger hole
        than the ledger closes. Counting it costs nothing and is the only trace
        a replay against a live session otherwise leaves.

    See Also
    --------
    QDSSession.transcript : Produces one.

    Examples
    --------
    >>> import json
    >>> import numpy as np
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession, SessionTranscript
    >>> transcript = QDSSession(
    ...     ProtocolParams(key_length=24), rng=np.random.default_rng(11)
    ... ).run(0)
    >>> restored = SessionTranscript.from_json(transcript.to_json())
    >>> restored == transcript
    True
    >>> transcript.symmetrised, transcript.forwarded_signature is None
    (True, True)
    """

    params: ProtocolParams
    message_bit: int
    signature: Signature
    records: tuple[RecipientRecord, ...]
    results: tuple[VerificationResult, ...]
    forwarded_signature: Signature | None = None
    run_id: str | None = None
    aborts: tuple[VerificationAbort, ...] = ()
    pooled: PooledMatchedCounts | None = None
    check_logs: tuple[CheckLog, ...] = ()
    channel: tuple[ChannelSample, ...] = ()
    signer_saw_recipient_logs: bool = False
    count_exchange_timing: str = COUNTS_BEFORE_FORWARDING
    spent_rounds: tuple[tuple[str, str, int], ...] = ()
    replay_refusals: tuple[tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        """Coerce the sequence fields to tuples and check the run hangs together.

        Raises
        ------
        TypeError
            If any field is of the wrong type.
        ValueError
            If ``message_bit`` is not ``0``/``1``, if either signature declares a
            different bit, if one party holds two outcomes (two verdicts, two
            refusals, or one of each), or if a result's ``threshold`` or an
            outcome's ``key_length`` disagrees with ``params``.
        """
        if not isinstance(self.params, ProtocolParams):
            raise TypeError(
                f"params must be a ProtocolParams, got "
                f"{type(self.params).__name__}"
            )
        object.__setattr__(
            self, "message_bit", _as_message_bit(self.message_bit)
        )
        if not isinstance(self.signature, Signature):
            raise TypeError(
                f"signature must be a Signature, got "
                f"{type(self.signature).__name__}"
            )
        if self.signature.message_bit != self.message_bit:
            raise ValueError(
                f"transcript is tagged with message bit {self.message_bit} but "
                f"holds a signature for bit {self.signature.message_bit}. The "
                f"bit selects which distribution the verifiers scored against, "
                f"so a mismatch means the verdicts in this transcript were "
                f"reached on the wrong records."
            )
        if self.count_exchange_timing not in COUNT_EXCHANGE_TIMINGS:
            raise ValueError(
                f"count_exchange_timing must be one of "
                f"{list(COUNT_EXCHANGE_TIMINGS)}, got "
                f"{self.count_exchange_timing!r}. It names which experiment "
                f"this run was, and the two give different answers to the same "
                f"attack, so an unrecognised value is a transcript nobody can "
                f"interpret."
            )
        object.__setattr__(
            self,
            "spent_rounds",
            tuple(
                (str(party), str(session_id), _as_message_bit(bit))
                for party, session_id, bit in self.spent_rounds
            ),
        )
        object.__setattr__(
            self,
            "replay_refusals",
            tuple(
                (str(party), int(count))
                for party, count in self.replay_refusals
            ),
        )
        object.__setattr__(self, "records", tuple(self.records))
        for position, record in enumerate(self.records):
            if not isinstance(record, RecipientRecord):
                raise TypeError(
                    f"records[{position}] must be a RecipientRecord, got "
                    f"{type(record).__name__}"
                )
        if self.forwarded_signature is not None:
            if not isinstance(self.forwarded_signature, Signature):
                raise TypeError(
                    f"forwarded_signature must be a Signature or None, got "
                    f"{type(self.forwarded_signature).__name__}"
                )
            if self.forwarded_signature.message_bit != self.message_bit:
                raise ValueError(
                    f"the forwarded declaration is for message bit "
                    f"{self.forwarded_signature.message_bit} but the transcript "
                    f"is tagged with bit {self.message_bit}. Bob forwards the "
                    f"declaration he was asked to verify; a different bit means "
                    f"Charlie was scored against another run entirely."
                )
        if self.run_id is not None and not isinstance(self.run_id, str):
            raise TypeError(
                f"run_id must be a string or None, got "
                f"{type(self.run_id).__name__}. It is a ledger key, carried "
                f"verbatim and interpreted by nothing in this module."
            )

        if not isinstance(self.signer_saw_recipient_logs, bool):
            raise TypeError(
                f"signer_saw_recipient_logs must be a bool, got "
                f"{type(self.signer_saw_recipient_logs).__name__}. It records "
                f"whether the signer seam was shown both recipients' raw logs, "
                f"which decides whether this run is inside the threat model at "
                f"all."
            )

        # Every verdict, refusal and count on this transcript was reached under
        # the *sifted* parameter set: check rounds carry no key, so the key
        # length they were scored against is params.signing_length. With no
        # check rounds the two sets are equal and this is the old behaviour
        # exactly. See :ref:`check-rounds`.
        scored = self.params.sifted()

        object.__setattr__(self, "results", tuple(self.results))
        seen: set[Party] = set()
        for position, result in enumerate(self.results):
            if not isinstance(result, VerificationResult):
                raise TypeError(
                    f"results[{position}] must be a VerificationResult, got "
                    f"{type(result).__name__}"
                )
            if result.party in seen:
                raise ValueError(
                    f"results holds two verdicts for "
                    f"{result.party.value!r}. One verifier reaches one decision "
                    f"per signature; a duplicate would make "
                    f"'did Charlie accept?' depend on which entry is read."
                )
            seen.add(result.party)
            _check_result_against(result, scored, self.message_bit)

        object.__setattr__(self, "aborts", tuple(self.aborts))
        for position, abort in enumerate(self.aborts):
            if not isinstance(abort, VerificationAbort):
                raise TypeError(
                    f"aborts[{position}] must be a VerificationAbort, got "
                    f"{type(abort).__name__}"
                )
            if abort.party in seen:
                raise ValueError(
                    f"{abort.party.value} appears in both results and aborts, "
                    f"or twice in aborts. Phase C leaves each verifier with "
                    f"exactly one outcome -- a verdict or a refusal to score, "
                    f"never both -- and a party in both fields would let "
                    f"'did Charlie accept?' depend on which field is read."
                )
            seen.add(abort.party)
            _check_abort_against(abort, scored, self.message_bit)

        if self.pooled is not None:
            if not isinstance(self.pooled, PooledMatchedCounts):
                raise TypeError(
                    f"pooled must be a PooledMatchedCounts or None, got "
                    f"{type(self.pooled).__name__}; "
                    f"tally.exchange_matched_counts returns exactly that."
                )
            _check_pooled_against(self.pooled, scored, self.message_bit)

        object.__setattr__(self, "check_logs", tuple(self.check_logs))
        published: dict[tuple[Party, int], CheckLog] = {}
        for position, log in enumerate(self.check_logs):
            if not isinstance(log, CheckLog):
                raise TypeError(
                    f"check_logs[{position}] must be a CheckLog, got "
                    f"{type(log).__name__}; "
                    f"distribute_public_key_with_checks returns one per party."
                )
            if (log.party, log.message_bit) in published:
                raise ValueError(
                    f"check_logs holds two logs for {log.party.value} on "
                    f"message bit {log.message_bit}. One recipient measures one "
                    f"link once per distribution, so a duplicate would double "
                    f"the sample behind every interval computed from it."
                )
            published[(log.party, log.message_bit)] = log

        object.__setattr__(self, "channel", tuple(self.channel))
        for position, sample in enumerate(self.channel):
            if not isinstance(sample, ChannelSample):
                raise TypeError(
                    f"channel[{position}] must be a ChannelSample, got "
                    f"{type(sample).__name__}."
                )
            _check_sample_against(sample, published, self.params)

    # -- derived views ------------------------------------------------------ #

    @property
    def results_by_party(self) -> dict[Party, VerificationResult]:
        """dict: The verdicts keyed by party, in the order they were reached."""
        return {result.party: result for result in self.results}

    @property
    def bob(self) -> VerificationResult | None:
        """VerificationResult or None: Bob's verdict, if he reached one."""
        return self.results_by_party.get(Party.BOB)

    @property
    def charlie(self) -> VerificationResult | None:
        """VerificationResult or None: Charlie's verdict, if he reached one."""
        return self.results_by_party.get(Party.CHARLIE)

    @property
    def aborts_by_party(self) -> dict[Party, VerificationAbort]:
        """dict: The refusals to score, keyed by party, in the order recorded."""
        return {abort.party: abort for abort in self.aborts}

    @property
    def aborted(self) -> bool:
        """bool: ``True`` iff some verifier reached no verdict at all.

        Distinct from ``not is_complete``, which is also ``True`` for a run
        simply abandoned before :meth:`QDSSession.transfer`. This one says a
        verifier *was* asked and refused to score, because the declaration left
        him a matched set below
        :func:`~sih141.protocol.verify.minimum_matched_count`. On an honest run
        it is ``False`` with probability at least
        ``1 - 2 * HONEST_ABORT_BUDGET``; when it is ``True``, the declaration or
        the distribution is what to investigate, not the verifiers.
        """
        return bool(self.aborts)

    @property
    def is_complete(self) -> bool:
        """bool: ``True`` when both verifiers have reached a verdict.

        ``False`` on an aborted run: a refusal to score is not a decision. Read
        :attr:`aborted` to tell "no verdict" from "not asked yet".
        """
        return self.bob is not None and self.charlie is not None

    @property
    def counts_exchanged(self) -> bool:
        """bool: ``True`` iff the recipients ran Phase C'.

        The pooled matched-count floor is checkable only after Bob and Charlie
        have compared counts (:mod:`sih141.protocol.tally`), so this says which
        rule the run's verdicts were reached under. ``False`` marks a run of the
        *pre-pooled* variant -- one made with
        :func:`sih141.protocol.tally.no_count_exchange`, which Phase 3 uses to
        demonstrate the split-coin repudiation route. Such a run enforces the
        per-verifier floor alone, has no unconditional non-repudiation guarantee
        below ``1/2``, and :meth:`summary` says so out loud.
        """
        return self.pooled is not None

    @property
    def channel_monitored(self) -> bool:
        """bool: ``True`` iff this run published per-check-round channel samples.

        ``False`` on every run of a parameter set without check rounds, and on
        a checked run whose ``distributor`` seam never called the channel seam
        at all -- an impersonator who substitutes his own states consumes no
        entanglement, and this says so rather than reporting a clean channel.
        """
        return bool(self.channel)

    @property
    def check_logs_by_party(self) -> dict[tuple[Party, int], CheckLog]:
        """dict: The published check logs, keyed by ``(party, message_bit)``."""
        return {(log.party, log.message_bit): log for log in self.check_logs}

    def check_log_for(
        self, party: Party | str, message_bit: int
    ) -> CheckLog | None:
        """Return one link's published check-round observations.

        Parameters
        ----------
        party : Party or str
            The recipient whose link is wanted. Alice is refused: a check round
            measures one link and she is the common endpoint of both.
        message_bit : int
            ``0`` or ``1``.

        Returns
        -------
        CheckLog or None
            ``None`` when the run published none, which is every run of a
            parameter set with ``check_fraction = 0``.

        Raises
        ------
        ValueError
            If ``party`` is Alice or names no party, or if ``message_bit`` is
            not ``0``/``1``.
        """
        resolved = _as_party(party)
        if resolved is Party.ALICE:
            raise ValueError(
                "Alice holds no check log: a check round is a statement about "
                "one link and she is at the far end of both. Ask for "
                "Party.BOB or Party.CHARLIE."
            )
        return self.check_logs_by_party.get(
            (resolved, _as_message_bit(message_bit))
        )

    def channel_for(
        self, party: Party | str, message_bit: int
    ) -> tuple[ChannelSample, ...]:
        """Return one link's channel samples, in the order the hops happened.

        Kept separate per link deliberately, as
        :func:`~sih141.protocol.distribute.distribute_public_key_with_checks`
        keeps the logs separate: Bob's link and Charlie's link are two channels,
        and a statistic that averages them detects neither one-sided attack.

        Parameters
        ----------
        party : Party or str
            The recipient whose link is wanted.
        message_bit : int
            ``0`` or ``1``.

        Returns
        -------
        tuple of ChannelSample
            Empty when the run published none.

        Raises
        ------
        ValueError
            If ``party`` is Alice or names no party, or if ``message_bit`` is
            not ``0``/``1``.
        """
        resolved = _as_party(party)
        if resolved is Party.ALICE:
            raise ValueError(
                "Alice holds no channel samples: they summarise the resource "
                "delivered on one recipient's link. Ask for Party.BOB or "
                "Party.CHARLIE."
            )
        bit = _as_message_bit(message_bit)
        return tuple(
            sample
            for sample in self.channel
            if sample.party is resolved and sample.message_bit == bit
        )

    @property
    def symmetrised(self) -> bool:
        """bool: ``True`` iff every log went through Phase A'.

        ``False`` marks a run of the *insecure* variant -- one made with
        :func:`sih141.protocol.symmetrise.no_symmetrisation`, which Phase 3 uses
        to demonstrate the repudiation attack. No non-repudiation claim attaches
        to such a run at any key length, and :meth:`summary` says so out loud.
        """
        return bool(self.records) and all(
            record.symmetrised for record in self.records
        )

    def signature_for(self, party: Party | str) -> Signature:
        """Return the declaration a given verifier actually scored.

        Parameters
        ----------
        party : Party or str
            :attr:`~sih141.protocol.params.Party.BOB` or
            :attr:`~sih141.protocol.params.Party.CHARLIE`.

        Returns
        -------
        Signature
            :attr:`signature` for Bob; :attr:`forwarded_signature` for Charlie
            when the forwarding hop altered it, and :attr:`signature` otherwise.

        Raises
        ------
        ValueError
            If ``party`` is :attr:`~sih141.protocol.params.Party.ALICE`, who
            scores nothing.
        TypeError
            If ``party`` is neither a :class:`~sih141.protocol.params.Party` nor
            a string.
        """
        resolved = _as_party(party)
        if resolved is Party.ALICE:
            raise ValueError(
                "Alice scores no declaration: she is the signer. Ask for "
                "Party.BOB (who received it) or Party.CHARLIE (who was "
                "forwarded it)."
            )
        if resolved is Party.CHARLIE and self.forwarded_signature is not None:
            return self.forwarded_signature
        return self.signature

    @property
    def forwarding_altered_signature(self) -> bool:
        """bool: ``True`` iff Charlie scored a different declaration from Bob."""
        return (
            self.forwarded_signature is not None
            and self.forwarded_signature != self.signature
        )

    @property
    def session_coherent(self) -> bool:
        """bool: ``True`` iff every scored log belongs to the declaration's round.

        A transcript is a record, so it will hold whatever it is given -- but
        two of its derived claims are claims about a *transaction*, and a
        declaration scored against another run's logs is not one. This is the
        check that says so. It was the missing one: before it existed, a
        transcript pairing one run's signature with another run's records and
        verdicts constructed without complaint and reported
        ``transferable=True``.

        Each verifier's log for the signed bit is compared against the
        declaration that verifier actually scored -- :attr:`signature` for Bob,
        :attr:`forwarded_signature` where there was one for Charlie -- using
        :attr:`~sih141.protocol.signature.Signature.session_id` and
        :attr:`~sih141.protocol.records.RecipientRecord.session_id`. A log that
        names no round is coherent with anything, which is what keeps every
        transcript written before the binding existed readable exactly as
        before.

        See Also
        --------
        sih141.protocol.verify.verify : Where the same comparison refuses to
            score rather than merely reporting.
        """
        for record in self.records:
            if (
                record.message_bit != self.message_bit
                or record.session_id is None
            ):
                continue
            scored = self.signature_for(record.party)
            if scored.session_id != record.session_id:
                return False
        return True

    @property
    def transferable(self) -> bool:
        """bool: ``True`` iff Bob accepted **and** Charlie accepted, in one round.

        The property the ``s_a < s_v`` gap exists to deliver: a signature Bob
        accepts is one he can forward. ``False`` while either verdict is still
        missing -- an unfinished run has not demonstrated transferability -- and
        ``False`` on a transcript whose verdicts and declaration come from
        different distribution rounds (:attr:`session_coherent`), because "both
        verifiers accepted" is a statement about one transaction and such a
        transcript records two.
        """
        return (
            self.bob is not None
            and self.charlie is not None
            and self.bob.accepted
            and self.charlie.accepted
            and self.session_coherent
        )

    @property
    def repudiated(self) -> bool:
        """bool: ``True`` iff Bob accepted and Charlie rejected *the same key*.

        The repudiation event, in which Bob holds a signature he cannot make
        stick. The scheme's non-repudiation claim is that this has probability
        exponentially small in ``L`` for any signer strategy **provided the
        recipients symmetrised** (:attr:`symmetrised`); without that step the
        claim is false at every ``L``, which is what
        :func:`sih141.protocol.symmetrise.no_symmetrisation` exists to show. On
        honest runs it should never be seen; Phase 3 tries to force it and Phase
        5 counts how often it succeeds.

        Gated on :attr:`session_coherent` for the same reason
        :attr:`transferable` is: "Bob accepted and Charlie did not" is a
        statement about one transaction, and on a transcript assembled from two
        rounds it would name a repudiation that no signer performed. On every
        run this module produces the gate is open, since a session stamps its
        own round on every log it hands out.

        **And gated on the forwarding hop having left the declaration alone**
        (:attr:`forwarding_altered_signature`), which is the same conservation
        argument :attr:`pooled_matched_count` already makes: repudiation is
        Alice disavowing *one* declaration, so it needs both verifiers to have
        scored one. When Bob himself supplied Charlie's -- the faithful
        recipient-forgery route, :ref:`forger-route` -- "Bob accepted and
        Charlie rejected" is the expected outcome of a *forgery* experiment and
        counting it as a repudiation would inflate a Phase 5 repudiation rate by
        one per attempted forgery. The same reading applies to a man in the
        middle on the classical link: he can deny the transfer, which is a
        different event from Alice repudiating and gets a different line in
        :meth:`summary`.
        """
        return (
            self.bob is not None
            and self.charlie is not None
            and self.bob.accepted
            and not self.charlie.accepted
            and not self.forwarding_altered_signature
            and self.session_coherent
        )

    @property
    def pooled_matched_count(self) -> int | None:
        """int or None: ``M = m_B + m_C`` as this run actually produced it.

        The evidence base the non-repudiation guarantee is stated over. ``None``
        unless the run is a repudiation experiment at all, which needs three
        things:

        * both verifiers reached a **verdict** -- a refusal to score
          (:attr:`aborts`) has no matched count to contribute, and counting it
          as zero would flatter the bound rather than weaken it;
        * both scored the **same declaration**, since ``m_B + m_C = M`` and
          ``e_B + e_C = E`` are conserved only across one fixed pair of records
          against one fixed declaration -- a run the forwarding hop altered
          (:attr:`forwarding_altered_signature`) is not one experiment but two;
        * the recipients **symmetrised** (:attr:`symmetrised`), because the
          coins are the only randomness the bound uses and without them there
          are none.

        Note what is *not* on that list: :attr:`counts_exchanged`. The per-run
        bound is a statement about the ``M`` a run produced, and a run produces
        one whether or not the recipients compared notes; what the exchange
        changes is which ``M`` values were *reachable*, which is the a-priori
        statement :func:`~sih141.protocol.verify.enforced_repudiation_bound`
        makes. On a run that did exchange, this agrees with
        :attr:`sih141.protocol.tally.PooledMatchedCounts.pooled` by
        construction.
        """
        if self.forwarding_altered_signature or not self.symmetrised:
            return None
        bob, charlie = self.bob, self.charlie
        if bob is None or charlie is None:
            return None
        return bob.matched_count + charlie.matched_count

    @property
    def repudiation_guarantee(self) -> float | None:
        """float or None: the per-run repudiation bound, from the observed ``M``.

        **The number this run is entitled to quote**, and the reason the
        property exists: it is
        :func:`sih141.protocol.analysis.repudiation_bound` evaluated at
        :attr:`pooled_matched_count`, which conditions on the two records *and*
        on the declaration and therefore holds for every Alice strategy with no
        independence assumption of any kind.

        Do **not** quote
        :func:`~sih141.protocol.analysis.averaged_repudiation_bound` for a run.
        Its ``6.9e-10`` at :data:`~sih141.protocol.params.DEFAULT_PARAMS`
        averages over ``M ~ Binomial(2L, 1/|B|)``, which is the law of the
        matched count only while the declaration is independent of the
        recipients' logged bases -- an assumption the ``Signer`` seam can be
        opened up to break (:ref:`two-log-signer`), and one whose failure is
        invisible in the averaged number. This property reads ``M`` off the run
        instead, so a starved run reports a number near ``1`` and says so,
        rather than inheriting a guarantee it did not earn. Restricting the
        seam's default narrowed who can break the assumption; it did not make
        the averaged number safe to quote per run, because a run's ``M`` is what
        a run's bound is a statement about.

        ``None`` exactly when :attr:`pooled_matched_count` is, plus the
        degenerate ``M = 0`` case, which cannot arise alongside two verdicts
        under the shipped floor.

        See Also
        --------
        sih141.protocol.verify.enforced_repudiation_bound : The a-priori
            counterpart, evaluated at the floor
            :func:`~sih141.protocol.verify.minimum_matched_count` enforces
            rather than at an observed count.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.session import QDSSession
        >>> transcript = QDSSession(
        ...     ProtocolParams(key_length=600), rng=np.random.default_rng(3)
        ... ).run(0)
        >>> transcript.pooled_matched_count > 2 * 600 // 3 - 60
        True
        >>> 0.0 < transcript.repudiation_guarantee < 1.0
        True
        """
        pooled = self.pooled_matched_count
        if pooled is None or pooled < 1:
            return None
        # The sifted set, always: sih141.protocol.analysis counts Bernoulli
        # trials against key_length directly, so a set with check rounds in it
        # would count the diverted positions as key and return a bound that is
        # too good. With no check rounds sifted() is this set (:ref:`check-rounds`).
        return repudiation_bound(self.params.sifted(), matched_records=pooled)

    def records_for(self, message_bit: int) -> dict[Party, RecipientRecord]:
        """Return the logs distributed for one message bit, keyed by party.

        Parameters
        ----------
        message_bit : int
            ``0`` or ``1``.

        Returns
        -------
        dict of Party to RecipientRecord
            The recipients' logs for that bit.

        Raises
        ------
        ValueError
            If ``message_bit`` is not ``0``/``1``.
        """
        bit = _as_message_bit(message_bit)
        return {
            record.party: record
            for record in self.records
            if record.message_bit == bit
        }

    def verdict_for(self, party: Party | str) -> VerificationResult:
        """Return one verifier's decision.

        Parameters
        ----------
        party : Party or str
            :attr:`~sih141.protocol.params.Party.BOB` or
            :attr:`~sih141.protocol.params.Party.CHARLIE`.

        Returns
        -------
        VerificationResult

        Raises
        ------
        ValueError
            If ``party`` names no verifier, or reached no verdict in this run --
            distinguishing "rejected" from "never asked" and from "asked and
            refused to score", none of which a ``None`` or a ``False`` would
            keep apart. When the party appears in :attr:`aborts` the message
            quotes the refusal.
        TypeError
            If ``party`` is neither a :class:`~sih141.protocol.params.Party` nor
            a string.
        """
        resolved = _as_party(party)
        result = self.results_by_party.get(resolved)
        if result is None:
            reached = sorted(item.value for item in self.results_by_party)
            abort = self.aborts_by_party.get(resolved)
            because = (
                f" He was asked and refused to score: {abort.summary()}"
                if abort is not None
                else ""
            )
            advice = (
                " Read transcript.aborts for the refusal."
                if abort is not None
                else (
                    " Run the session to completion with "
                    "QDSSession.run(message_bit), or call verify(Party.BOB) "
                    "and then transfer()."
                )
            )
            raise ValueError(
                f"{resolved.value} reached no verdict in this run; verdicts "
                f"present: {reached or 'none'}. This is not a rejection: no "
                f"decision was made.{because}{advice}"
            )
        return result

    def summary(self) -> str:
        """Return a short human-readable account of the whole run.

        Returns
        -------
        str
            One line of context followed by one line per verdict, each from
            :meth:`~sih141.protocol.verify.VerificationResult.summary`, then one
            line per refusal to score from
            :meth:`~sih141.protocol.verify.VerificationAbort.summary`, then --
            on any run that is a repudiation experiment -- the evidence line
            carrying :attr:`pooled_matched_count` and
            :attr:`repudiation_guarantee`, and a closing line naming the outcome
            in protocol terms. The evidence line is printed rather than left to
            be looked up because the number a reader reaches for otherwise is
            the ``M``-averaged one, which is not valid against a signer who
            reads the recipients' logs. On a run where a
            verifier reached no verdict the closing line says so instead of
            naming a composite event, because none of ``TRANSFERABLE``,
            ``REPUDIATION`` and ``REJECTED`` is true of a run with no decision
            in it. Two further closing lines exist for the same reason:
            ``NOT TRANSFERRED`` for a run whose forwarding hop altered the
            declaration -- Bob accepted, so ``REJECTED`` would be false, and
            Charlie scored a different key, so ``REPUDIATION`` would credit
            Alice with somebody else's attack -- and ``INCOHERENT`` for a
            transcript whose logs and declaration come from different rounds.
            The context lines above them name an over-powered signer seam and a
            run that spent positions on check rounds, both of which change what
            the numbers below mean.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.session import QDSSession
        >>> text = QDSSession(
        ...     ProtocolParams(key_length=24), rng=np.random.default_rng(4)
        ... ).run(0).summary()
        >>> text.splitlines()[-1]
        'TRANSFERABLE: Bob accepted and Charlie accepted.'
        """
        lines = [
            f"QDS run on message bit {self.message_bit}: L="
            f"{self.params.key_length}, |B|={len(self.params.bases)}, "
            f"s_a={self.params.s_a:.5f}, s_v={self.params.s_v:.5f}"
        ]
        if not self.symmetrised:
            lines.append(
                "UNSYMMETRISED: the recipients did not exchange their copies, "
                "so this run has no non-repudiation guarantee at any L."
            )
        if not self.counts_exchanged:
            lines.append(
                "UNPOOLED: the recipients did not compare matched counts, so "
                "only the per-verifier floor applied and a signer who splits "
                "the evidence base repudiates at about 1/2 at any L."
            )
        if self.signer_saw_recipient_logs:
            lines.append(
                "OVER-POWERED SIGNER: the signer seam was shown both "
                "recipients' raw logs, which no single adversary in the threat "
                "model holds. Nothing here checks what it read, so no number "
                "from this run describes the shipped scheme unless the attack "
                "itself stayed inside the model."
            )
        if self.check_logs or self.channel:
            rounds = sum(log.round_count for log in self.check_logs)
            lines.append(
                f"CHECK ROUNDS: {self.params.check_count} of "
                f"{self.params.key_length} positions were reserved for "
                f"channel estimation and dealt between the links, so the key "
                f"was scored at L={self.params.signing_length}; {rounds} "
                f"observations and {len(self.channel)} channel samples "
                f"published."
            )
        if self.forwarding_altered_signature:
            lines.append(
                "FORWARDING ALTERED THE DECLARATION: Charlie scored a "
                "different key from the one Bob was given."
            )
        if self.pooled is not None:
            lines.append(self.pooled.summary())
        lines.extend(result.summary() for result in self.results)
        lines.extend(abort.summary() for abort in self.aborts)
        guarantee = self.repudiation_guarantee
        if guarantee is not None:
            lines.append(
                f"EVIDENCE: M = m_B + m_C = {self.pooled_matched_count} matched "
                f"records, so P(repudiation | this run) <= {guarantee:.3e}. "
                f"This is the per-run bound and the only one that assumes "
                f"nothing about the signer."
            )
        if self.aborted:
            # Name the reason each verifier actually gave. A hardcoded cause here
            # was wrong for six of the eight AbortReason members, and on an
            # altered-forwarding run it read "the matched set was below the floor"
            # two lines under "Every floor met." -- the reason must come from the
            # abort, never from an assumption about which one fired.
            refused = ", ".join(
                f"{abort.party.value} ({abort.reason.value})" for abort in self.aborts
            )
            lines.append(
                f"NO VERDICT: {refused} could not score this declaration. "
                f"This is not a rejection and must not be counted as one."
            )
        elif not self.is_complete:
            lines.append("INCOMPLETE: not every verifier reached a verdict.")
        elif self.transferable:
            lines.append("TRANSFERABLE: Bob accepted and Charlie accepted.")
        elif self.repudiated:
            lines.append(
                "REPUDIATION: Bob accepted a signature Charlie rejected."
            )
        elif not self.verdict_for(Party.BOB).accepted:
            lines.append("REJECTED: Bob did not accept the signature.")
        elif not self.session_coherent:
            # Bob accepted, so "REJECTED" would be a false statement, and the
            # two composite events are gated off. Say which gate closed.
            lines.append(
                "INCOHERENT: the verdicts in this transcript were reached on "
                "logs from a different distribution round than the declaration "
                "they are filed against, so neither transferability nor "
                "repudiation is a statement about it."
            )
        else:
            # Bob accepted and the hop altered the declaration: whatever Charlie
            # did, he did to a different key. Naming this REPUDIATION would
            # credit Alice with an attack the forwarding hop performed -- the
            # recipient-forgery route lands here on every run.
            lines.append(
                "NOT TRANSFERRED: Bob accepted, but Charlie was handed a "
                "different declaration, so this run measures the forwarding "
                "hop and not the signer. It is not a repudiation."
            )
        return "\n".join(lines)

    # -- serialisation ------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the entire run.

        Nothing derived is stored: :attr:`transferable` and friends are
        recomputed from the verdicts on the way back in, so a transcript on disk
        cannot disagree with itself.

        Returns
        -------
        dict
            Keys ``"params"``, ``"message_bit"``, ``"signature"``, ``"records"``,
            ``"results"``, ``"aborts"``, ``"pooled"``,
            ``"forwarded_signature"``, ``"run_id"``, ``"check_logs"``,
            ``"channel"``, ``"signer_saw_recipient_logs"``,
            ``"count_exchange_timing"`` and ``"spent_rounds"``. Every leaf is an
            :class:`int`, :class:`float`, :class:`bool`, :class:`str`, ``None``
            or a :class:`enum.StrEnum` member (which *is* a string), so the
            result passes to :func:`json.dumps` unchanged -- including whatever
            a ``channel_monitor`` contributed, which
            :class:`ChannelSample` coerced to JSON leaves when it was recorded
            rather than leaving for the encoder to fail on.

        Examples
        --------
        >>> import json
        >>> import numpy as np
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.session import QDSSession
        >>> blob = QDSSession(
        ...     ProtocolParams(key_length=24), rng=np.random.default_rng(6)
        ... ).run(1).to_dict()
        >>> json.loads(json.dumps(blob))["message_bit"]
        1
        """
        return {
            "params": self.params.to_dict(),
            "message_bit": self.message_bit,
            "signature": self.signature.to_dict(),
            "records": [record.to_dict() for record in self.records],
            "results": [result.to_dict() for result in self.results],
            "aborts": [abort.to_dict() for abort in self.aborts],
            "pooled": None if self.pooled is None else self.pooled.to_dict(),
            "forwarded_signature": (
                None
                if self.forwarded_signature is None
                else self.forwarded_signature.to_dict()
            ),
            "run_id": self.run_id,
            "check_logs": [log.to_dict() for log in self.check_logs],
            "channel": [sample.to_dict() for sample in self.channel],
            "signer_saw_recipient_logs": self.signer_saw_recipient_logs,
            "count_exchange_timing": self.count_exchange_timing,
            "spent_rounds": [list(entry) for entry in self.spent_rounds],
            "replay_refusals": [list(entry) for entry in self.replay_refusals],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SessionTranscript:
        """Rebuild a transcript from :meth:`to_dict` output.

        Parameters
        ----------
        data : mapping
            Must contain ``"params"``, ``"message_bit"``, ``"signature"``,
            ``"records"`` and ``"results"``. ``"forwarded_signature"``,
            ``"run_id"`` and ``"pooled"`` are optional and default to ``None``;
            ``"aborts"``, ``"check_logs"`` and ``"channel"`` are optional and
            default to empty, and ``"signer_saw_recipient_logs"`` defaults to
            ``False``, so a transcript written before the matched-count abort
            rule, the count exchange, the check rounds or the signer
            restriction existed still restores -- as a run that had none of
            them, which is the truth about it.

        Returns
        -------
        SessionTranscript
            Equal to the original.

        Raises
        ------
        KeyError
            If a field is missing.
        ValueError
            If the restored run is not self-consistent -- which now includes
            each verdict's ``threshold`` and ``key_length`` agreeing with
            ``params``. This is the hand-off boundary for Phases 4 to 6, so a
            transcript whose Bob verdict carries Charlie's ``s_v`` -- internally
            consistent, and reporting ``transferable=True`` for a run Bob
            genuinely rejected -- is refused here rather than believed. It also
            includes every channel sample sitting at a position the run's own
            check log recorded (:func:`_check_sample_against`): a file claiming
            per-position channel diagnostics for a *key* position describes a
            protocol in which the sample was not a sample.
        """
        forwarded = data.get("forwarded_signature")
        return cls(
            params=ProtocolParams.from_dict(data["params"]),
            message_bit=data["message_bit"],
            signature=Signature.from_dict(data["signature"]),
            records=tuple(
                RecipientRecord.from_dict(item) for item in data["records"]
            ),
            results=tuple(
                VerificationResult.from_dict(item) for item in data["results"]
            ),
            forwarded_signature=(
                None if forwarded is None else Signature.from_dict(forwarded)
            ),
            run_id=data.get("run_id"),
            # Optional, and defaulting to none, so that a transcript written
            # before the abort rule existed still restores: it can only have
            # recorded verdicts.
            aborts=tuple(
                VerificationAbort.from_dict(item)
                for item in data.get("aborts", ())
            ),
            # Optional for the same reason: a transcript written before the
            # count exchange existed restores as one whose recipients did not
            # compare counts, which is exactly what it was.
            pooled=(
                None
                if data.get("pooled") is None
                else PooledMatchedCounts.from_dict(data["pooled"])
            ),
            # Optional, and empty by default, for the third time and the same
            # reason: a transcript written before check rounds existed published
            # no channel statistics and had no over-powered signer, which is
            # what it restores as.
            check_logs=tuple(
                CheckLog.from_dict(item) for item in data.get("check_logs", ())
            ),
            channel=tuple(
                ChannelSample.from_dict(item)
                for item in data.get("channel", ())
            ),
            signer_saw_recipient_logs=bool(
                data.get("signer_saw_recipient_logs", False)
            ),
            # Optional, and defaulting to the shipped ordering, for the fourth
            # time and the same reason: every transcript written before the
            # ordering was a choice was written under the ordering that was
            # then the only one, which is the one this default names.
            count_exchange_timing=str(
                data.get("count_exchange_timing", COUNTS_BEFORE_FORWARDING)
            ),
            spent_rounds=tuple(
                (str(party), str(session_id), int(bit))
                for party, session_id, bit in data.get("spent_rounds", ())
            ),
            replay_refusals=tuple(
                (str(party), int(count))
                for party, count in data.get("replay_refusals", ())
            ),
        )

    def to_json(self, **kwargs: Any) -> str:
        """Serialise the run to a JSON string.

        Parameters
        ----------
        **kwargs
            Forwarded to :func:`json.dumps` -- ``indent=2`` for a file a human
            will read, nothing for the compact form a Phase 6 endpoint returns.

        Returns
        -------
        str
            JSON text that :meth:`from_json` restores exactly.
        """
        return json.dumps(self.to_dict(), **kwargs)

    @classmethod
    def from_json(cls, text: str) -> SessionTranscript:
        """Rebuild a transcript from :meth:`to_json` output.

        Parameters
        ----------
        text : str
            JSON text.

        Returns
        -------
        SessionTranscript
        """
        return cls.from_dict(json.loads(text))


# --------------------------------------------------------------------------- #
# The session
# --------------------------------------------------------------------------- #


class QDSSession:
    """One run of the protocol: distribute, sign, verify, transfer.

    Stateful by nature -- the four phases happen in order and each depends on
    the last -- so this is a class rather than a function, and it refuses calls
    made out of order with a message saying what to call instead. It is
    single-use: see the module docstring on replay.

    Parameters
    ----------
    params : ProtocolParams, optional
        The parameter set. Defaults to
        :data:`~sih141.protocol.params.DEMO_PARAMS` (``L = 192``), which is fast
        enough to watch run and carries **no security claim**; use
        :data:`~sih141.protocol.params.DEFAULT_PARAMS` for a number worth
        quoting.
    resource_factory : callable or None, optional
        Keyword-only. The quantum-channel seam, forwarded verbatim to the
        distributor and invoked once per key position per recipient. ``None``
        selects :func:`~sih141.protocol.distribute.ideal_resource`. See
        :ref:`phase3-seams`.
    payload_map : callable or None, optional
        Keyword-only. The payload-line seam, forwarded to the distributor and
        invoked once per key round with the eigenstate about to be teleported.
        ``None`` sends what Alice prepared. See :ref:`phase3-seams` and
        :ref:`sih141.protocol.distribute <payload-seam>`.
    channel_monitor : ChannelMonitor or None, optional
        Keyword-only. Extra per-check-round diagnostics for a Phase 4 detector,
        called with the resource and the hop's
        :class:`~sih141.protocol.distribute.ResourceContext` and recorded in
        :attr:`SessionTranscript.channel`. ``None`` records the built-in
        summary alone. Ignored entirely on a parameter set without check
        rounds, because there is no round it would be legitimate to call it on.
    distributor : Distributor or None, optional
        Keyword-only. The Phase A seam. ``None`` selects
        :func:`~sih141.protocol.distribute.distribute_public_key_with_checks`,
        whose records are identical to
        :func:`~sih141.protocol.distribute.distribute_public_key`'s -- the
        latter is a wrapper over the former -- and which additionally returns
        the check logs a checked run publishes.
    symmetriser : Symmetriser or None, optional
        Keyword-only. The Phase A' seam -- the *recipients'* step, not Alice's.
        ``None`` selects
        :func:`~sih141.protocol.symmetrise.symmetrise_records`. Phase 3 passes
        :func:`~sih141.protocol.symmetrise.no_symmetrisation` to run the
        insecure variant and measure the repudiation attack the step defends
        against.
    signer : Signer or None, optional
        Keyword-only. The Phase B seam. ``None`` selects
        :func:`honest_signer`.
    signer_sees_recipient_logs : bool, optional
        Keyword-only, and ``False`` by default. Hands the ``signer`` seam both
        recipients' **raw** logs instead of :data:`NO_RECIPIENT_LOGS`. That is
        strictly more than any single adversary in the threat model holds, so a
        run made this way is outside the model the bounds are stated for; it is
        available because those attacks are worth measuring, and every run made
        with it is flagged in the transcript and named in
        :meth:`SessionTranscript.summary`. See :ref:`two-log-signer`, and
        :ref:`forger-route` for why a *forging recipient* does not need this
        flag at all.
    count_exchange : CountExchange or None, optional
        Keyword-only. The Phase C' seam -- again the *recipients'* step, not
        Alice's. ``None`` selects
        :func:`~sih141.protocol.tally.exchange_matched_counts`. Phase 3 passes
        :func:`~sih141.protocol.tally.no_count_exchange` to run the pre-pooled
        variant and measure the split-coin repudiation route the exchange
        closes.
    forwarder : Forwarder or None, optional
        Keyword-only. The Bob-to-Charlie hop. ``None`` selects
        :func:`honest_forwarder`, the identity.
    run_id : str or None, optional
        Keyword-only. Carried verbatim into the transcript for an
        application-level ledger to key on; used by nothing here. See the module
        docstring on why it is not generated.
    context : str or None, optional
        Keyword-only. What the signed bit *means* to the application, together
        with a freshness nonce --
        :func:`sih141.protocol.signature.fresh_context` builds one. It is hashed
        into every round identifier this session announces, so it is fixed here,
        at distribution time, and not at signing time: a context chosen after
        the recipients had already recorded their identifiers would be a label
        nothing covers, which is exactly what
        :mod:`sih141.protocol.signature` refuses to carry. Two authorisations of
        one instruction under different nonces are two rounds, and each verifier
        decides each round once, which is how a valid signed instruction is
        stopped from being executed twice.
    rng : numpy.random.Generator or None, optional
        Keyword-only (D3). Resolved once, in this constructor, and drawn from
        once: :data:`_STREAM_MATERIAL_BYTES` bytes of material, from which two
        independent streams are derived (:ref:`two-streams`). Alice's is
        threaded through key generation and both distributions and is what the
        ``distributor`` seam receives; the recipients' supplies both
        symmetrisations and is shown to no Alice-side seam. One seed still
        reproduces the whole run. The generator passed in is not retained, so
        constructing two sessions from one generator gives two different runs,
        as before.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`, if any seam is neither
        ``None`` nor callable, if ``run_id`` is neither ``None`` nor a string,
        or if ``rng`` is neither ``None`` nor a
        :class:`numpy.random.Generator`.

    See Also
    --------
    SessionTranscript : What a finished run leaves behind.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.params import Party, ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> session = QDSSession(
    ...     ProtocolParams(key_length=24), rng=np.random.default_rng(2)
    ... )
    >>> _ = session.distribute()
    >>> _ = session.sign(0)
    >>> session.verify(Party.BOB).accepted
    True
    >>> session.transfer().accepted
    True
    >>> session.transcript().transferable
    True
    """

    def __init__(
        self,
        params: ProtocolParams = DEMO_PARAMS,
        *,
        resource_factory: ResourceFactory | None = None,
        payload_map: PayloadMap | None = None,
        channel_monitor: ChannelMonitor | None = None,
        distributor: Distributor | None = None,
        symmetriser: Symmetriser | None = None,
        signer: Signer | None = None,
        signer_sees_recipient_logs: bool = False,
        count_exchange: CountExchange | None = None,
        count_exchange_timing: str = COUNTS_BEFORE_FORWARDING,
        forwarder: Forwarder | None = None,
        run_id: str | None = None,
        context: str | None = None,
        rng: np.random.Generator | None = None,
    ) -> None:
        if not isinstance(params, ProtocolParams):
            raise TypeError(
                f"params must be a ProtocolParams, got {type(params).__name__}. "
                f"Use DEMO_PARAMS for a quick run or DEFAULT_PARAMS for the "
                f"security-grade set."
            )
        _check_seam(
            resource_factory,
            "resource_factory",
            "a callable returning a two-qubit entanglement resource, taking "
            "either no arguments or one ResourceContext; leave it None for the "
            "ideal |Phi+> pair",
        )
        _check_seam(
            payload_map,
            "payload_map",
            "a callable payload_map(state, context) returning the one-qubit "
            "state to teleport; leave it None to send the eigenstate Alice "
            "prepared",
        )
        _check_seam(
            channel_monitor,
            "channel_monitor",
            "a callable monitor(resource, context) returning a JSON-safe "
            "mapping of extra check-round diagnostics",
        )
        _check_seam(
            distributor,
            "distributor",
            "a callable with the signature of distribute_public_key_with_checks",
        )
        _check_seam(
            symmetriser,
            "symmetriser",
            "a callable with the signature of symmetrise_records; pass "
            "no_symmetrisation to run the insecure variant deliberately",
        )
        _check_seam(
            signer, "signer", "a callable with the signature of honest_signer"
        )
        _check_seam(
            count_exchange,
            "count_exchange",
            "a callable with the signature of exchange_matched_counts; pass "
            "no_count_exchange to run the pre-pooled variant deliberately",
        )
        _check_seam(
            forwarder,
            "forwarder",
            "a callable with the signature of honest_forwarder",
        )
        if count_exchange_timing not in COUNT_EXCHANGE_TIMINGS:
            raise ValueError(
                f"count_exchange_timing must be one of "
                f"{list(COUNT_EXCHANGE_TIMINGS)}, got "
                f"{count_exchange_timing!r}. It decides *which declaration* "
                f"each recipient counts against, which is a different "
                f"experiment and not a tuning knob: "
                f"{COUNTS_BEFORE_FORWARDING!r} counts the declaration Alice "
                f"signed at both verifiers, {COUNTS_AFTER_FORWARDING!r} counts "
                f"whatever each one received."
            )
        if not isinstance(signer_sees_recipient_logs, bool):
            raise TypeError(
                f"signer_sees_recipient_logs must be a bool, got "
                f"{type(signer_sees_recipient_logs).__name__}. It is the "
                f"opt-in that hands the signer seam more than any adversary in "
                f"the threat model holds, so it is a deliberate yes or no and "
                f"not a value to be inferred."
            )
        if run_id is not None and not isinstance(run_id, str):
            raise TypeError(
                f"run_id must be a string or None, got "
                f"{type(run_id).__name__}. It is a ledger key carried into the "
                f"transcript verbatim; this module never reads it."
            )
        if context is not None and not isinstance(context, str):
            raise TypeError(
                f"context must be a string or None, got "
                f"{type(context).__name__}. It is the application's "
                f"instruction-and-nonce string -- build one with "
                f"sih141.protocol.signature.fresh_context(instruction, nonce) "
                f"-- and it is hashed into every round identifier this session "
                f"announces, so it is fixed here and not at signing time."
            )

        self._params = params
        # What every record, declaration, floor and bound in this run is scored
        # against. `params` ITSELF unless it reserves check rounds, in which
        # case its key_length is the signing length -- see :ref:`check-rounds`.
        # Identity rather than equality on the common branch, so that a seam
        # handed this object still receives the very object the caller passed.
        self._scored_params = (
            params.sifted() if params.has_check_rounds else params
        )
        self._resource_factory = resource_factory
        self._payload_map = payload_map
        self._channel_monitor = channel_monitor
        self._distributor: Distributor = (
            distribute_public_key_with_checks
            if distributor is None
            else distributor
        )
        self._symmetriser: Symmetriser = (
            symmetrise_records if symmetriser is None else symmetriser
        )
        self._signer: Signer = honest_signer if signer is None else signer
        self._signer_sees_recipient_logs = signer_sees_recipient_logs
        self._count_exchange: CountExchange = (
            exchange_matched_counts
            if count_exchange is None
            else count_exchange
        )
        self._count_exchange_timing = count_exchange_timing
        self._forwarder: Forwarder = (
            honest_forwarder if forwarder is None else forwarder
        )
        # Decided once, before anything runs, exactly as the resource factory's
        # arity is: a forwarder that can be called with two arguments is called
        # with two, so only one that *requires* a view is built one. See
        # :class:`Forwarder`.
        self._forwarder_wants_view = _forwarder_wants_view(self._forwarder)
        self._run_id = run_id
        self._context = context
        # One draw from the caller's generator, then three independent streams
        # derived from it -- Alice's, which the seams may see, the recipients',
        # which they may not, and the binding stream the session keeps to
        # itself. See :ref:`two-streams` and :data:`_BINDING_STREAM_LABEL`. The
        # caller's generator is not retained: a seam that was handed it could
        # rewind it to whatever the other streams were derived from.
        material = resolve_rng(rng).bytes(_STREAM_MATERIAL_BYTES)
        self._alice_rng = _derive_stream(material, _ALICE_STREAM_LABEL)
        self._recipient_rng = _derive_stream(material, _RECIPIENT_STREAM_LABEL)
        self._binding_rng = _derive_stream(material, _BINDING_STREAM_LABEL)

        self._keys: tuple[PrivateKey, PrivateKey] | None = None
        self._signing_keys: tuple[PrivateKey, PrivateKey] | None = None
        self._plans: dict[int, CheckRoundPlan] = {}
        self._check_logs: dict[tuple[Party, int], CheckLog] = {}
        self._channel: list[ChannelSample] = []
        self._openings: dict[int, str] = {}
        self._session_ids: dict[int, str] = {}
        self._raw_records: dict[int, dict[Party, RecipientRecord]] = {}
        self._records: dict[int, dict[Party, RecipientRecord]] = {}
        self._signature: Signature | None = None
        self._forwarded: Signature | None = None
        self._pooled: PooledMatchedCounts | None = None
        self._counts_compared = False
        self._results: dict[Party, VerificationResult] = {}
        self._aborts: dict[Party, VerificationAbort] = {}
        # How many times each verifier was asked to decide a round he had
        # already decided. Counted rather than recorded as an outcome, because
        # a replay refusal must not displace the verdict that spent the round
        # (see verify()) -- and counted at all because otherwise a replay
        # against a live session leaves no trace in the transcript whatsoever,
        # which a Phase 4 detector cannot work with.
        self._replay_refusals: dict[Party, int] = {}
        # One ledger per verifier, never one shared between them: the two are
        # adversaries to each other in half of this package's attacks, so Bob's
        # history must not be reachable from Charlie's decision. See
        # :ref:`sih141.protocol.verify <replay>`.
        self._ledgers: dict[Party, ConsumedRecords] = {
            party: ConsumedRecords(party) for party in VERIFIERS
        }

    def __repr__(self) -> str:
        """Return a debugging representation naming the phase reached.

        Refusals to score are named as well as verdicts, because "verified by
        B" and "verified by B, no verdict from Charlie" are very different runs
        and the first would otherwise stand for both.
        """
        if self._signature is None:
            stage = "distributed" if self._keys is not None else "new"
        else:
            reached = "".join(
                party.value[0]
                for party in VERIFIERS
                if party in self._results
            )
            refused = ", ".join(
                party.value for party in VERIFIERS if party in self._aborts
            )
            stage = (
                f"signed bit {self._signature.message_bit}"
                + (f", verified by {reached}" if reached else "")
                + (f", no verdict from {refused}" if refused else "")
            )
        return (
            f"QDSSession(L={self._params.key_length}, "
            f"s_a={self._params.s_a}, s_v={self._params.s_v}, {stage})"
        )

    # -- read-only state ---------------------------------------------------- #

    @property
    def params(self) -> ProtocolParams:
        """ProtocolParams: The parameter set this run executes under."""
        return self._params

    @property
    def scored_params(self) -> ProtocolParams:
        """ProtocolParams: The set every record and verdict is checked against.

        :meth:`params.sifted() <sih141.protocol.params.ProtocolParams.sifted>`:
        identical to :attr:`params` unless the run reserves check rounds, in
        which case its ``key_length`` is the signing length, because the check
        positions carry no key. Both matched-count floors and the repudiation
        bound are derived from it. See :ref:`check-rounds`.
        """
        return self._scored_params

    @property
    def check_plans(self) -> dict[int, CheckRoundPlan]:
        """dict: The check-round plan for each message bit, keyed by bit.

        Empty on a parameter set without check rounds. Drawn from the
        **recipients'** stream, never Alice's, so that the party being estimated
        cannot choose the sample; a fresh dict per access, and the plans
        themselves are frozen.
        """
        return dict(self._plans)

    @property
    def check_logs(self) -> dict[tuple[Party, int], CheckLog]:
        """dict: The published check observations, keyed by ``(party, bit)``.

        What the recipients would announce. Empty until :meth:`distribute` has
        run, and on any run whose ``distributor`` seam returned bare records
        rather than
        :class:`~sih141.protocol.distribute.RecipientDistribution` objects.
        """
        return dict(self._check_logs)

    @property
    def channel(self) -> tuple[ChannelSample, ...]:
        """tuple of ChannelSample: One summary per check round, in hop order.

        The channel-monitor seam's output (:ref:`phase3-seams`). Empty unless
        the run has check rounds *and* the distributor actually drew resources
        from the channel seam. Never holds a key position.
        """
        return tuple(self._channel)

    @property
    def is_distributed(self) -> bool:
        """bool: ``True`` once Phase A has run."""
        return self._keys is not None

    @property
    def is_signed(self) -> bool:
        """bool: ``True`` once Phase B has run."""
        return self._signature is not None

    @property
    def is_complete(self) -> bool:
        """bool: ``True`` once both verifiers have reached a verdict."""
        return self.is_signed and all(
            party in self._results for party in VERIFIERS
        )

    @property
    def keys(self) -> tuple[PrivateKey, PrivateKey]:
        """tuple of PrivateKey: Alice's committed pair ``(k_0, k_1)``.

        Raises
        ------
        ValueError
            Before :meth:`distribute` has run, when no keys exist.
        """
        if self._keys is None:
            raise self._not_yet(
                "no keys have been drawn", "session.distribute()"
            )
        return self._keys

    @property
    def signing_keys(self) -> tuple[PrivateKey, PrivateKey]:
        """tuple of PrivateKey: The pair Alice may actually declare.

        :attr:`keys` with the check positions removed
        (:meth:`~sih141.protocol.checkrounds.CheckRoundPlan.sift_key`), which is
        what the :class:`Signer` seam is handed. **The same objects as**
        :attr:`keys` when the run reserves no check rounds, so a test asserting
        ``signature.declared_key is session.keys[b]`` holds unchanged there.

        The distinction is the whole of :ref:`check-rounds` at signing time:
        Alice draws and distributes ``L`` elements because she does not know
        which the recipients will spend on the channel, and declares the
        ``signing_length`` of them that survived, because the others were never
        prepared and no recipient can score them.

        Raises
        ------
        ValueError
            Before :meth:`distribute` has run.
        """
        if self._signing_keys is None:
            raise self._not_yet(
                "no keys have been drawn", "session.distribute()"
            )
        return self._signing_keys

    @property
    def records(self) -> dict[int, dict[Party, RecipientRecord]]:
        """dict: Recipients' logs, keyed by message bit then by party.

        A fresh nested :class:`dict` per access, so a caller cannot reach in and
        edit the session's evidence; the
        :class:`~sih141.protocol.records.RecipientRecord` values are frozen
        anyway.

        Raises
        ------
        ValueError
            Before :meth:`distribute` has run.
        """
        if not self._records:
            raise self._not_yet(
                "nothing has been distributed", "session.distribute()"
            )
        return {bit: dict(byparty) for bit, byparty in self._records.items()}

    @property
    def raw_records(self) -> dict[int, dict[Party, RecipientRecord]]:
        """dict: The recipients' logs *before* the symmetrisation exchange.

        What each recipient measured for himself, keyed by message bit then by
        party. The verifiers are scored on :attr:`records`, not on these; this
        view exists because a recipient-flavoured adversary declares his own
        measurements (after the exchange, half of them *are* the other
        verifier's evidence) and because Phase 3 needs to compare the two.

        **This is the harness's view, not an adversary's.** It holds both
        recipients' logs, which nobody in the threat model does, so it is the
        thing to narrow before handing anything to an attack: build one
        :class:`~sih141.protocol.records.RecipientView` per verifier with
        :func:`~sih141.protocol.records.recipient_views`, which is what the
        ``forwarder`` seam is given. The :class:`Signer` seam is handed this
        mapping only on a session built with
        ``signer_sees_recipient_logs=True`` (:ref:`two-log-signer`).

        A fresh nested :class:`dict` per access, as :attr:`records`.

        Raises
        ------
        ValueError
            Before :meth:`distribute` has run.
        """
        if not self._raw_records:
            raise self._not_yet(
                "nothing has been distributed", "session.distribute()"
            )
        return {bit: dict(byparty) for bit, byparty in self._raw_records.items()}

    @property
    def signature(self) -> Signature:
        """Signature: The declaration under verification.

        Raises
        ------
        ValueError
            Before :meth:`sign` has run.
        """
        if self._signature is None:
            raise self._not_yet(
                "nothing has been signed", "session.sign(message_bit)"
            )
        return self._signature

    @property
    def results(self) -> dict[Party, VerificationResult]:
        """dict: Verdicts so far, keyed by party, in the order reached."""
        return dict(self._results)

    @property
    def aborts(self) -> dict[Party, VerificationAbort]:
        """dict: Verifiers who were asked and reached no verdict, keyed by party.

        A verifier lands here instead of in :attr:`results` when the evidence
        base failed one of the matched-count floors -- his own, the pooled one,
        or his counterpart's. Empty on every healthy run, and a party is never
        in both mappings.
        """
        return dict(self._aborts)

    @property
    def pooled(self) -> PooledMatchedCounts | None:
        """PooledMatchedCounts or None: what Phase C' produced.

        ``None`` before :meth:`exchange_counts` has run, and also after it on a
        session wired with
        :func:`~sih141.protocol.tally.no_count_exchange`. Read
        :attr:`counts_compared` to tell those two apart.
        """
        return self._pooled

    @property
    def counts_compared(self) -> bool:
        """bool: ``True`` once Phase C' has been attempted.

        Distinct from ``pooled is not None``, which is also ``False`` when the
        seam deliberately skipped the comparison.
        """
        return self._counts_compared

    @property
    def session_ids(self) -> dict[int, str]:
        """dict: The identifier of each distribution round, keyed by message bit.

        What Alice announced with the states in Phase A and what every log from
        this run is stamped with. Public from distribution time -- it names a
        round, it does not open it.

        Raises
        ------
        ValueError
            Before :meth:`distribute` has run, when no round exists to name.
        """
        if not self._session_ids:
            raise self._not_yet(
                "no distribution round has been opened", "session.distribute()"
            )
        return dict(self._session_ids)

    def opening_for(self, message_bit: int) -> str:
        """Return the secret opening of one round, for a dispute.

        The value the round identifier commits to. It is revealed on the
        signature for the bit that gets signed, and this accessor is how an
        auditor obtains the *other* one -- the round Alice never signed -- in
        order to check that the identifier she announced for it was really a
        commitment and not a fabricated string. Recomputing
        :func:`~sih141.protocol.signature.session_identifier` from it must
        reproduce :attr:`session_ids`; nothing else can, short of a preimage
        search.

        Parameters
        ----------
        message_bit : int
            ``0`` or ``1``.

        Returns
        -------
        str
            The 32-hex-character opening.

        Raises
        ------
        ValueError
            If ``message_bit`` is not ``0``/``1``, or before :meth:`distribute`
            has run.
        """
        bit = _as_message_bit(message_bit)
        if not self._openings:
            raise self._not_yet(
                "no distribution round has been opened", "session.distribute()"
            )
        return self._openings[bit]

    def ledger_for(self, party: Party | str) -> ConsumedRecords:
        """Return one verifier's ledger of rounds he has already decided.

        Read-only in practice: the object is the live one this session hands
        :func:`sih141.protocol.verify.verify`, and it is exposed so that a
        harness can see what a verifier has spent, not so that anything can
        spend on his behalf. Each verifier has his own; there is no way to
        obtain a view of both, which is the point (:ref:`sih141.protocol.verify
        <replay>`).

        Parameters
        ----------
        party : Party or str
            :attr:`~sih141.protocol.params.Party.BOB` or
            :attr:`~sih141.protocol.params.Party.CHARLIE`.

        Returns
        -------
        ConsumedRecords

        Raises
        ------
        ValueError
            If ``party`` is Alice, who reaches no verdict and spends nothing.
        """
        resolved = _as_party(party)
        if resolved not in self._ledgers:
            raise ValueError(
                f"{resolved.value} keeps no consumed-records ledger: only the "
                f"verifiers reach verdicts, so only they have rounds to spend. "
                f"Ask for Party.BOB or Party.CHARLIE."
            )
        return self._ledgers[resolved]

    # -- Phase A ------------------------------------------------------------ #

    def distribute(self) -> dict[int, dict[Party, RecipientRecord]]:
        """Run Phase A: draw both keys and teleport both public keys to both.

        Draws ``(k_0, k_1)`` with
        :func:`~sih141.protocol.keys.generate_key_pair`, then calls the
        :class:`Distributor` seam once per message bit, each call serving both
        :data:`~sih141.protocol.params.VERIFIERS`. Four classical logs come back
        and every teleported qubit has already been measured and discarded: when
        this returns, the session holds no quantum state.

        Returns
        -------
        dict of int to (dict of Party to RecipientRecord)
            The logs, keyed by message bit then by party.

        Raises
        ------
        ValueError
            If this session has already distributed (it is single-use -- see the
            module docstring on replay), or if the :class:`Distributor` seam
            returned something that is not one well-formed record per verifier
            for the bit requested.
        TypeError
            If the seam returned a non-mapping, or a non-record value.

        Notes
        -----
        Consumes, from the **Alice-side** stream, ``4 * L`` variates for the key
        pair and ``3 * L`` per recipient per bit for the teleportation and
        measurement -- three per position on both branches of a checked run, so
        the count does not depend on the plan; and from the **recipient-side**
        stream, per bit, the check-round plan (nothing at all when the parameter
        set reserves none) followed by one array of symmetrisation coins, one
        per position of the *sifted* record. Two streams, not one, and the seams
        are handed only the first (D3, :ref:`two-streams`): the coins are the
        only randomness the non-repudiation bound uses, and the plan is the
        sample Alice must not be able to steer, so a generator an Alice-side
        seam can read is a generator that has neither in it.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.session import QDSSession
        >>> records = QDSSession(
        ...     ProtocolParams(key_length=12), rng=np.random.default_rng(8)
        ... ).distribute()
        >>> sorted(records), sorted(records[0])
        ([0, 1], [<Party.BOB: 'Bob'>, <Party.CHARLIE: 'Charlie'>])
        """
        if self._keys is not None:
            raise ValueError(
                "this session has already distributed its public keys. A "
                "session is single-use: the key states are consumed on receipt, "
                "and redistributing under the same session would either reuse a "
                "key whose states are gone or silently replace evidence the "
                "verifiers have already been scored against. Build a new "
                "QDSSession for the next message."
            )

        keys = generate_key_pair(self._params, rng=self._alice_rng)
        signing_keys: list[PrivateKey] = []
        openings: dict[int, str] = {}
        session_ids: dict[int, str] = {}
        raw_records: dict[int, dict[Party, RecipientRecord]] = {}
        records: dict[int, dict[Party, RecipientRecord]] = {}
        for bit in MESSAGE_BITS:
            # The recipients draw the check-round plan first, and from THEIR
            # stream: the value of a sampled estimate is that the estimated
            # party cannot choose the sample, and Alice's seams never see this
            # generator (:ref:`two-streams`, :ref:`check-rounds`). Nothing is
            # drawn at all when the parameter set reserves no check rounds, so
            # every seeded transcript predating this feature is unmoved.
            plan = (
                draw_check_plan(self._params, rng=self._recipient_rng)
                if self._params.has_check_rounds
                else None
            )
            if plan is not None:
                self._plans[bit] = plan
            # The round's opening, drawn from the session's own stream so that
            # the two the seams and the recipients use are untouched, and its
            # identifier, which Alice announces with the distribution. The
            # opening stays here until Phase B reveals it on the signature. See
            # :ref:`sih141.protocol.signature <session-binding>`.
            openings[bit] = fresh_opening(rng=self._binding_rng)
            session_ids[bit] = session_identifier(
                bit,
                self._scored_params.key_length,
                opening=openings[bit],
                context=self._context,
            )
            returned = self._distributor(
                keys[bit],
                self._params,
                parties=VERIFIERS,
                # The channel seam, tapped on EVERY hop of a checked run --
                # the monitor is called everywhere and a ChannelSample is
                # recorded only at this link's check positions
                # (:class:`_ChannelTap`). The tap is downstream of the factory
                # and cannot be seen from it; with no plan the seam is passed
                # through untouched, arity and all.
                resource_factory=(
                    self._resource_factory
                    if plan is None
                    else _ChannelTap(
                        self._resource_factory,
                        plan=plan,
                        monitor=self._channel_monitor,
                        sink=self._channel,
                    )
                ),
                # Alice's stream, and only ever Alice's: a distributor that
                # clones this generator's state learns nothing about the coins
                # tossed on the next line. See :ref:`two-streams`.
                rng=self._alice_rng,
                # Passed only when in force, so a seam written before either
                # existed is called exactly as before. See :class:`Distributor`.
                **({} if plan is None else {"check_plan": plan}),
                **(
                    {}
                    if self._payload_map is None
                    else {"payload_map": self._payload_map}
                ),
            )
            signing_keys.append(
                keys[bit] if plan is None else plan.sift_key(keys[bit])
            )
            raw = {
                party: record.with_session_id(session_ids[bit])
                for party, record in self._check_distribution(
                    returned, bit, collect_logs=True
                ).items()
            }
            # Phase A': the recipients' own step, applied to whatever the
            # distributor produced -- an adversary standing in Alice's place
            # cannot skip it, because he does not run it, and cannot read its
            # coins, because they are drawn from a generator he is never given.
            exchanged = self._symmetriser(raw, rng=self._recipient_rng)
            raw_records[bit] = raw
            # Re-stamped after the exchange as well as before it. Each recipient
            # heard the announcement himself and re-attaches it to whatever log
            # he ends up holding, so a symmetriser seam cannot strip the
            # recipients' own binding on the way through -- which would leave
            # them scoring unbound evidence and quietly reopen the replay route.
            records[bit] = {
                party: record.with_session_id(session_ids[bit])
                for party, record in self._check_distribution(
                    exchanged, bit
                ).items()
            }

        self._keys = keys
        # The same tuple object on an unchecked run, not merely an equal one:
        # `signature.declared_key is session.keys[b]` is a claim worth keeping
        # true, and it is the honest description of a run that sifted nothing.
        self._signing_keys = (
            keys if not self._plans else (signing_keys[0], signing_keys[1])
        )
        self._openings = openings
        self._session_ids = session_ids
        self._raw_records = raw_records
        self._records = records
        return self.records

    def _check_distribution(
        self, returned: Any, message_bit: int, *, collect_logs: bool = False
    ) -> dict[Party, RecipientRecord]:
        """Validate one distributor call's return value.

        The :class:`Distributor` seam is the widest hole in the module, so its
        output is checked for *shape* before the session will build on it: an
        attack that returns the wrong party, the wrong bit or the wrong length
        must fail here, loudly, rather than surface later as an unexplained
        rejection that would be scored as a successful detection.

        Parameters
        ----------
        returned : Any
            Whatever the seam produced: one
            :class:`~sih141.protocol.records.RecipientRecord` per party, or one
            :class:`~sih141.protocol.distribute.RecipientDistribution` per
            party, which additionally carries that link's check log.
        message_bit : int
            The bit it was asked to distribute for.
        collect_logs : bool, optional
            Keyword-only. Whether to keep any check logs the values carry.
            ``True`` for the distributor's own output and ``False`` for the
            symmetriser's, which is the same records a second time: a check log
            describes a *link*, and the private exchange that runs between the
            recipients afterwards is not one.

        Returns
        -------
        dict of Party to RecipientRecord
            ``returned``, keyed by :class:`~sih141.protocol.params.Party`.

        Raises
        ------
        TypeError
            If ``returned`` is not a mapping, or holds a value that is neither
            a record nor a distribution.
        ValueError
            If a verifier is missing, if a record is tagged with another party
            or another message bit, or if a record does not belong to
            :attr:`scored_params` -- which on a checked run is shorter than
            ``params``, because the check positions carry no key.
        """
        if not isinstance(returned, Mapping):
            raise TypeError(
                f"the distributor seam must return a mapping of Party to "
                f"RecipientRecord or to RecipientDistribution, got "
                f"{type(returned).__name__} for message bit {message_bit}; "
                f"distribute_public_key_with_checks returns exactly that."
            )
        checked: dict[Party, RecipientRecord] = {}
        for party, value in returned.items():
            resolved = _as_party(party)
            record = value
            if isinstance(value, RecipientDistribution):
                record = value.record
                if collect_logs and value.log.round_count:
                    if (
                        value.log.party is not resolved
                        or value.log.message_bit != message_bit
                    ):
                        raise ValueError(
                            f"the distributor seam filed a check log for "
                            f"{value.log.party.value} on message bit "
                            f"{value.log.message_bit} under "
                            f"{resolved.value} on bit {message_bit}. A check "
                            f"log is a published statement about one link, so a "
                            f"swap would attribute one recipient's channel to "
                            f"the other -- which is exactly the attribution a "
                            f"one-sided attack turns on."
                        )
                    # An EMPTY log is dropped rather than filed. Every run
                    # without check rounds produces four of them, and carrying
                    # those would put "this run published no statistics" into
                    # the transcript as four objects rather than as an absence
                    # -- changing the serialised form of every honest run for
                    # no information at all.
                    self._check_logs[(resolved, message_bit)] = value.log
            if not isinstance(record, RecipientRecord):
                raise TypeError(
                    f"the distributor seam returned "
                    f"{type(value).__name__} for {resolved.value} on message "
                    f"bit {message_bit}; a RecipientRecord, or a "
                    f"RecipientDistribution holding one, is required."
                )
            if record.party is not resolved:
                raise ValueError(
                    f"the distributor seam keyed a record by "
                    f"{resolved.value!r} that is tagged {record.party.value!r}. "
                    f"The key selects the acceptance threshold, so a swap would "
                    f"score one verifier's evidence against the other's cut."
                )
            if record.message_bit != message_bit:
                raise ValueError(
                    f"the distributor seam returned a record for message bit "
                    f"{record.message_bit} while distributing for bit "
                    f"{message_bit}. Each bit gets its own key and its own "
                    f"distribution; crossing them would verify a declaration "
                    f"against states that were never sent for it."
                )
            # Against the *sifted* set: with check rounds in force the record
            # that comes back is already shorter, and checking it against the
            # unsifted length would refuse every checked run.
            record.check_against(self._scored_params)
            checked[resolved] = record

        missing = [party.value for party in VERIFIERS if party not in checked]
        if missing:
            raise ValueError(
                f"the distributor seam produced no record for {missing} on "
                f"message bit {message_bit}. Both verifiers are required: "
                f"transferability and non-repudiation are statements about Bob "
                f"and Charlie together, and a session without Charlie cannot "
                f"express either."
            )
        return checked

    # -- Phase B ------------------------------------------------------------ #

    def sign(self, message_bit: int) -> Signature:
        """Run Phase B: declare a key for ``message_bit``.

        Calls the :class:`Signer` seam, which on an honest run
        (:func:`honest_signer`) declares ``keys[message_bit]`` verbatim. The
        declaration travels to Bob over an authenticated classical channel; this
        module models that channel as reliable, because authentication of the
        *classical* link is an assumption of the scheme rather than something it
        provides.

        Parameters
        ----------
        message_bit : int
            ``0`` or ``1``.

        Returns
        -------
        Signature
            The declaration the verifiers will score.

        Raises
        ------
        ValueError
            If :meth:`distribute` has not run; if this session has already
            signed; if ``message_bit`` is not ``0``/``1``; or if the
            :class:`Signer` seam returned a signature for a different bit or of
            the wrong length.
        TypeError
            If the seam returned something that is not a
            :class:`~sih141.protocol.signature.Signature`.

        Notes
        -----
        Consumes no randomness (D3): an adversarial signer that wants some draws
        its own generator over, which keeps the session's two streams -- and
        therefore the distribution and the coins -- identical between a clean
        run and an attacked one. It is offered no generator to draw from in any
        case; see :ref:`two-streams`.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.session import QDSSession
        >>> session = QDSSession(
        ...     ProtocolParams(key_length=12), rng=np.random.default_rng(9)
        ... )
        >>> _ = session.distribute()
        >>> session.sign(1).declared_key is session.keys[1]
        True
        """
        if self._keys is None:
            raise self._not_yet(
                "there is nothing to sign against", "session.distribute()"
            )
        if self._signature is not None:
            raise ValueError(
                f"this session has already signed message bit "
                f"{self._signature.message_bit}. One distribution supports one "
                f"signature: signing the other bit as well would hand a "
                f"verifier two declarations scored against logs drawn from the "
                f"same run, and the independence every bound assumes would be "
                f"gone. Build a new QDSSession."
            )
        bit = _as_message_bit(message_bit)

        # Nothing, by default: no adversary in the threat model holds a
        # recipient's log at signing time, and the seam that was handed both of
        # them is where every repudiation attack in the Phase 2 audit started.
        # The opt-in hands over the *raw* logs -- not the post-exchange ones,
        # since the exchange is private to the recipients -- and the transcript
        # says so. See :ref:`two-log-signer`.
        signature = self._signer(
            bit,
            self.signing_keys,
            self._scored_params,
            records=(
                self.raw_records
                if self._signer_sees_recipient_logs
                else NO_RECIPIENT_LOGS
            ),
        )
        if not isinstance(signature, Signature):
            raise TypeError(
                f"the signer seam must return a Signature, got "
                f"{type(signature).__name__}. Even a forgery is a Signature -- "
                f"it is a declaration, and what makes it a forgery is that the "
                f"key inside it is not the one whose states were distributed."
            )
        if signature.message_bit != bit:
            raise ValueError(
                f"the signer seam was asked for message bit {bit} and returned "
                f"a signature for bit {signature.message_bit}. The bit selects "
                f"which distribution the verifiers score against, so the two "
                f"must agree; a signer that wants to attack the other bit "
                f"should be asked to sign that bit."
            )
        signature.check_against(self._scored_params)
        signature = self._bind_to_round(signature)

        self._signature = signature
        return signature

    def _bind_to_round(self, signature: Signature) -> Signature:
        """Attach this run's opening and context to a declaration.

        Phase B reveals the opening of the round whose states were distributed,
        and it is *this* session that ran that distribution, so the opening is
        supplied here rather than taken from whatever the seam returned. A seam
        is free to declare any key it likes -- that is the point of the
        :class:`Signer` and :class:`Forwarder` seams -- but it does not get to
        say which round the declaration belongs to, and overriding rather than
        trusting is what keeps that true.

        The consequence is worth stating, because it is the difference between
        a useful measurement and an empty one: a forging seam's declaration
        carries the *correct* round identifier, so it is scored and rejected on
        its mismatch rate exactly as before. If the seam could leave the round
        unnamed, every forgery would abort as
        :attr:`~sih141.protocol.verify.AbortReason.SESSION_MISMATCH` and the
        whole of Phase 3's forgery table would empty into the no-verdict column.
        The binding is a replay defence, never a key check; see
        :ref:`sih141.protocol.verify <replay>`.

        Parameters
        ----------
        signature : Signature
            Whatever the seam produced, already checked for bit and shape.

        Returns
        -------
        Signature
            The same declaration, naming this session's round for its bit. The
            declared key object is shared, not copied.
        """
        opening = self._openings.get(signature.message_bit)
        if opening is None:
            return signature
        return Signature(
            message_bit=signature.message_bit,
            declared_key=signature.declared_key,
            session_opening=opening,
            context=self._context,
        )

    # -- Phase C' ----------------------------------------------------------- #

    def exchange_counts(self) -> PooledMatchedCounts | None:
        """Run Phase C': Bob and Charlie compare how much evidence each holds.

        Each recipient computes :func:`~sih141.protocol.tally.matched_count_message`
        from **his own** post-symmetrisation log against the declaration, the two
        messages cross, and the ``count_exchange`` seam combines them into the
        :class:`~sih141.protocol.tally.PooledMatchedCounts` both of them end up
        holding. Nothing but two integers moves between the verifiers here; the
        reason that matters is in :mod:`sih141.protocol.tally`.

        Idempotent, and called automatically by :meth:`verify` the first time a
        verdict is asked for, so a caller who follows the older
        ``distribute / sign / verify / transfer`` sequence still gets the pooled
        rule. :meth:`run` calls it explicitly, in phase order, because the step
        is a message rather than an implementation detail.

        **Which declaration is counted** is the session's
        ``count_exchange_timing``, and it is a different experiment rather than a
        tuning knob -- see :meth:`_declaration_counted`.

        Under :data:`COUNTS_BEFORE_FORWARDING`, the default and the ordering this
        package shipped with, it is the one Alice sent Bob -- the declaration Bob
        forwards to Charlie in order to *ask* for a count. Charlie therefore
        holds it before Bob's verdict is final, which is the real ordering cost
        of the pooled rule: Bob's acceptance is no longer local. If the
        ``forwarder`` seam later hands Charlie a *different* declaration, the
        counts pooled here are not the counts Charlie scored, the run is not one
        repudiation experiment but two, and
        :attr:`SessionTranscript.pooled_matched_count` already returns ``None``
        for it (:attr:`SessionTranscript.forwarding_altered_signature`). That
        ordering is also, and only incidentally, what stops an adversary on the
        hop burning Charlie's round: his own count names a declaration he is not
        scoring, so he refuses rather than deciding
        (:ref:`sih141.protocol.verify <ledger-denial>`).

        Under :data:`COUNTS_AFTER_FORWARDING` it is the declaration that reached
        *Charlie*, for both recipients, and this call raises until
        :meth:`forward` has run because Charlie cannot count against a
        declaration he is not holding. The forging hop is then scored on its
        merits instead of refused, which is the arm in which the shipped
        protocol's recipient-forgery rate is defined at all.

        Either way both messages name **one** declaration, so the pooled count is
        a real ``M`` for a real declaration and the floor derived from it means
        what it says.

        Returns
        -------
        PooledMatchedCounts or None
            ``None`` when the seam declined to compare -- which is what
            :func:`~sih141.protocol.tally.no_count_exchange` does, and what a
            Phase 3 experiment measuring the split-coin route wants.

        Raises
        ------
        ValueError
            If :meth:`sign` has not run: there is no declaration to count
            against, and counting against a key nobody declared would pool two
            numbers about nothing. Also, under
            :data:`COUNTS_AFTER_FORWARDING`, if :meth:`forward` has not run --
            Charlie is not holding a declaration yet, and the message names the
            fix.
        TypeError
            If the ``count_exchange`` seam returned something that is neither a
            :class:`~sih141.protocol.tally.PooledMatchedCounts` nor ``None``.

        Notes
        -----
        Consumes no randomness (D3), so a session with the exchange and one
        without draw the identical generator sequence and stay comparable
        position by position.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.session import QDSSession
        >>> session = QDSSession(
        ...     ProtocolParams(key_length=600), rng=np.random.default_rng(4)
        ... )
        >>> _ = session.distribute()
        >>> _ = session.sign(0)
        >>> pooled = session.exchange_counts()
        >>> pooled.pooled == pooled.bob_count + pooled.charlie_count
        True
        >>> pooled.meets_every_floor
        True
        """
        if self._signature is None:
            raise self._not_yet(
                "there is no declaration for the recipients to count against",
                "session.sign(message_bit)",
            )
        after = self._count_exchange_timing == COUNTS_AFTER_FORWARDING
        if after and self._forwarded is None:
            raise self._not_yet(
                "this session counts against the declaration each recipient "
                "received, and the hop has not happened yet, so Charlie is not "
                "holding one",
                "session.forward()",
            )
        if self._counts_compared:
            return self._pooled

        bit = self._signature.message_bit
        # Each message is built from that recipient's own log and nothing else:
        # the count is local, the comparison is not. *Which* declaration each
        # one counts is the count_exchange_timing question -- see
        # :data:`COUNTS_AFTER_FORWARDING`.
        counted = self._declaration_counted()
        messages: dict[Party, MatchedCountMessage] = {
            party: matched_count_message(
                counted, self._records[bit][party], self._scored_params
            )
            for party in VERIFIERS
        }
        pooled = self._count_exchange(messages, self._scored_params)
        if pooled is not None and not isinstance(pooled, PooledMatchedCounts):
            raise TypeError(
                f"the count_exchange seam must return a PooledMatchedCounts or "
                f"None, got {type(pooled).__name__}. Returning None means the "
                f"recipients did not compare counts, which is what "
                f"no_count_exchange does; anything else is a wiring error."
            )
        self._pooled = pooled
        self._counts_compared = True
        return pooled

    def _declaration_counted(self) -> Signature:
        """Return the declaration Phase C' counts against, under either timing.

        Alice's under :data:`COUNTS_BEFORE_FORWARDING`: that ordering runs the
        exchange before the hop exists, so it is the only declaration there is.

        Under :data:`COUNTS_AFTER_FORWARDING` it is the one that *reached
        Charlie*, for **both** recipients -- and the asymmetry that produces is
        the point rather than an oversight. An adversary who owns the
        Bob-to-Charlie hop owns the declaration channel and the count channel
        alike, because in a deployment they are the same link; so he announces a
        count against the declaration he is passing on, Charlie's provenance
        check compares like with like and passes, and Charlie scores the forgery
        on its merits. That is the arm in which the *shipped* protocol's
        recipient-forgery rate is defined at all.

        Bob is then counting a declaration he is not scoring, so his own
        provenance check refuses -- correctly. A party cannot both announce a
        count against ``D'`` and reach a verdict on ``D``; a real forging Bob
        does not try, because he has nothing to gain from his own verdict and
        every reason to want Charlie's. His refusal is recorded as a refusal,
        never as a rejection.

        Returns
        -------
        Signature
            The declaration both matched counts are taken against.
        """
        assert self._signature is not None  # callers check
        if (
            self._count_exchange_timing == COUNTS_AFTER_FORWARDING
            and self._forwarded is not None
        ):
            return self._forwarded
        return self._signature

    def forward(self) -> Signature:
        """Run the Bob-to-Charlie hop, without verifying at the far end.

        Split out of :meth:`transfer` because the two orderings of Phase C'
        need the hop at different moments: under
        :data:`COUNTS_BEFORE_FORWARDING` the counts are taken first and the hop
        can stay inside :meth:`transfer`, while under
        :data:`COUNTS_AFTER_FORWARDING` Charlie must be holding a declaration
        before he can count against one, which is *before* Bob's verdict.

        Idempotent: the hop happens once per run, and a second call returns the
        declaration the first one produced rather than consulting the seam
        again. An adversary offered the seam twice would get two chances to
        substitute, and a run with two hops is not this protocol.

        Returns
        -------
        Signature
            What the ``forwarder`` seam passed on, bound to this run's round
            (:meth:`_bind_to_round`). On an honest run this is the object Bob
            scored.

        Raises
        ------
        ValueError
            If :meth:`sign` has not run, or if the seam returned a declaration
            for the other message bit.
        TypeError
            If the seam returned something that is not a
            :class:`~sih141.protocol.signature.Signature`.

        Notes
        -----
        Consumes no randomness (D3). Unlike :meth:`transfer` it does **not**
        require Bob to have verified: under the after-forwarding ordering he
        cannot have, and the view the seam is offered carries no matched count
        in that case, which is the honest representation of a hop taken before
        its owner had a verdict.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.protocol.params import Party, ProtocolParams
        >>> from sih141.protocol.session import (
        ...     COUNTS_AFTER_FORWARDING, QDSSession)
        >>> session = QDSSession(
        ...     ProtocolParams(key_length=192),
        ...     count_exchange_timing=COUNTS_AFTER_FORWARDING,
        ...     rng=np.random.default_rng(7),
        ... )
        >>> _ = session.distribute()
        >>> _ = session.sign(0)
        >>> forwarded = session.forward()
        >>> session.forward() is forwarded
        True
        >>> pooled = session.exchange_counts()
        >>> pooled.meets_every_floor
        True
        >>> session.verify(Party.BOB).accepted, session.transfer().accepted
        (True, True)
        """
        if self._signature is None:
            raise self._not_yet(
                "there is no declaration to forward", "session.sign(message_bit)"
            )
        if self._forwarded is not None:
            return self._forwarded
        forwarded = self._call_forwarder(self._signature)
        if not isinstance(forwarded, Signature):
            raise TypeError(
                f"the forwarder seam must return a Signature, got "
                f"{type(forwarded).__name__}. Charlie scores a declaration; an "
                f"attack on the forwarding hop alters that declaration, it does "
                f"not remove it."
            )
        if forwarded.message_bit != self._signature.message_bit:
            raise ValueError(
                f"the forwarder seam returned a signature for message bit "
                f"{forwarded.message_bit} while forwarding one for bit "
                f"{self._signature.message_bit}. The bit selects which "
                f"distribution Charlie scores against, so changing it would "
                f"verify against states that were never sent for this run."
            )
        forwarded.check_against(self._scored_params)
        # Bound to this run's round for the same reason the signed declaration
        # is: the hop can alter the declaration -- that is what the seam is for
        # -- but Charlie is still in this round, and a hop that could also
        # unname the round would convert every altered-forwarding detection
        # into a no-verdict. See _bind_to_round.
        self._forwarded = self._bind_to_round(forwarded)
        return self._forwarded

    # -- Phase C ------------------------------------------------------------ #

    def verify(self, party: Party | str = Party.BOB) -> VerificationResult:
        """Run Phase C for one verifier against his own log.

        Delegates to :func:`sih141.protocol.verify.verify`, which builds the
        matched set, counts disagreements **within it only** and compares the
        rate against the threshold ``params`` assigns to ``party`` -- ``s_a``
        for Bob, ``s_v`` for Charlie. The session chooses neither the threshold
        nor the rule.

        Parameters
        ----------
        party : Party or str, optional
            The verifier. Defaults to
            :attr:`~sih141.protocol.params.Party.BOB`, who is the first
            recipient and the one Alice signs to.

        Returns
        -------
        VerificationResult
            The verdict, also stored on the session.

        Raises
        ------
        ValueError
            If :meth:`sign` has not run; if ``party`` is
            :attr:`~sih141.protocol.params.Party.ALICE`, who verifies nothing;
            or for any reason :func:`sih141.protocol.verify.verify` raises.
        MatchedSetTooSmall
            A :class:`ValueError` subclass, if the evidence base failed one of
            the matched-count floors: this verifier's own
            (:func:`~sih141.protocol.verify.minimum_matched_count`), the pooled
            one (:func:`~sih141.protocol.verify.minimum_pooled_matched_count`),
            or the other verifier's own -- which takes this one down with it,
            because the floor's consequence is joint. The corresponding
            :class:`~sih141.protocol.verify.VerificationAbort` is recorded in
            :attr:`aborts` **before** the exception propagates, so a caller that
            catches it -- :meth:`run` does -- still gets the run in the
            transcript. It is not a rejection and must not be counted as one.
        TypeError
            If ``party`` is neither a :class:`~sih141.protocol.params.Party` nor
            a string.

        Notes
        -----
        **One verdict per verifier per round, and asking twice is refused.**
        This used to be a repeatable pure call; it is now backed by a
        per-verifier :class:`~sih141.protocol.verify.ConsumedRecords`, so a
        second :meth:`verify` for the same party aborts as
        :attr:`~sih141.protocol.verify.AbortReason.RECORD_ALREADY_VERIFIED`
        rather than re-deciding. That is the replay defence and not an
        implementation accident: a captured declaration re-presented after the
        run collected a fresh acceptance every time it was offered, measured
        3/3 before the ledger existed. Read the verdict already reached from
        :attr:`results` instead of asking again. Consumes no randomness (D3).

        A refusal spends nothing, so a verifier who aborted can be asked again
        once the cause is fixed -- which is what lets :meth:`transfer` re-verify
        Charlie against a forwarded declaration after an abort on the
        unforwarded one. Each verifier holds exactly one current outcome, so a
        call that reaches a verdict clears any refusal recorded for that party,
        and vice versa -- with the single exception of the replay refusal, which
        leaves the standing verdict alone. Recording it as this verifier's
        outcome would let a replayed presentation *delete* the acceptance that
        spent the round, which would be a larger hole than the one the ledger
        closes.
        """
        if self._signature is None:
            raise self._not_yet(
                "there is no signature to verify", "session.sign(message_bit)"
            )
        resolved = _as_party(party)
        if resolved is Party.ALICE:
            raise ValueError(
                "Alice cannot verify: she is the signer, holds no measurement "
                "record and has no acceptance threshold. Verify at Party.BOB "
                "(cut at s_a) or Party.CHARLIE (cut at s_v)."
            )

        record = self._records[self._signature.message_bit][resolved]
        declaration = self._signature
        if resolved is Party.CHARLIE and self._forwarded is not None:
            # Charlie scores what the forwarding hop actually delivered, which
            # on an honest run is the same object Bob scored.
            declaration = self._forwarded
        # Phase C' if it has not happened yet: a verifier applies the pooled
        # floor, so he needs the number the other one sent him. Lazily here
        # rather than only in run(), so that the older
        # distribute/sign/verify/transfer sequence gets the pooled rule too.
        pooled = self.exchange_counts()
        counterpart = None if pooled is None else pooled.counterpart_of(resolved)
        try:
            # The module-level verify(), not this method. The ledger handed over
            # is this verifier's own and nobody else's, so asking twice is
            # refused as the replay it is, and Bob's history stays out of
            # Charlie's decision. See :ref:`sih141.protocol.verify <replay>`.
            result = verify(
                declaration,
                record,
                self._scored_params,
                counterpart_matched=counterpart,
                ledger=self._ledgers[resolved],
            )
        except MatchedSetTooSmall as too_small:
            # Recorded *before* it propagates, so that run() -- and any harness
            # that catches it -- reports a no-verdict outcome instead of losing
            # the run. A starved matched set is a plumbing failure, never a
            # rejection, so it is stored in a different field and a different
            # type from the verdicts.
            #
            # With one exception, and it matters: a refusal to decide a round
            # *again* is not a new outcome for this verifier, it is the old one
            # standing. Overwriting the verdict with it would let a replayed
            # presentation delete the acceptance that spent the round -- turning
            # the replay defence into a way of erasing the very decision it
            # protects, which is a worse hole than the one it closes.
            if too_small.abort.reason is AbortReason.RECORD_ALREADY_VERIFIED:
                self._replay_refusals[resolved] = (
                    self._replay_refusals.get(resolved, 0) + 1
                )
            if (
                too_small.abort.reason is AbortReason.RECORD_ALREADY_VERIFIED
                and resolved in self._results
            ):
                raise
            self._results.pop(resolved, None)
            self._aborts[resolved] = too_small.abort
            raise
        # Phase C leaves each verifier exactly one current outcome. Re-verifying
        # Charlie against a forwarded declaration after an abort on the
        # unforwarded one must replace the refusal, not sit beside it.
        self._aborts.pop(resolved, None)
        self._results[resolved] = result
        return result

    def transfer(self) -> VerificationResult:
        """Forward the signature from Bob to Charlie and verify it there.

        The step the whole construction exists for. Charlie scores **his own**
        log -- Bob forwards the declaration, never his evidence, which is why
        Bob cannot help a signature along -- and cuts at ``s_v``. Because
        ``s_v > s_a``, a signature inside Bob's tight cut is overwhelmingly
        likely to sit inside Charlie's looser one, and that is transferability;
        because ``s_a > 0`` *and* the recipients symmetrised, Alice cannot aim a
        declaration into the gap between them, and that is non-repudiation.

        The declaration passes through the ``forwarder`` seam on the way, so an
        attack on the Bob-to-Charlie hop is expressible; on an honest run
        :func:`honest_forwarder` returns the same object and the transcript's
        :attr:`~SessionTranscript.forwarded_signature` stays ``None``.

        Returns
        -------
        VerificationResult
            Charlie's verdict, also stored on the session. Pair it with Bob's:
            :attr:`SessionTranscript.transferable` and
            :attr:`SessionTranscript.repudiated` are the two events worth
            naming, and neither is visible from one verdict.

        Raises
        ------
        TypeError
            If the ``forwarder`` seam returned something that is not a
            :class:`~sih141.protocol.signature.Signature`.
        ValueError
            If Bob has not run Phase C at all -- there is nothing to *transfer*
            before the holder has looked, and running the two verifications in
            the wrong order would misrepresent what Bob knew when he forwarded
            -- or if the forwarded declaration is for another message bit.
        MatchedSetTooSmall
            A :class:`ValueError` subclass, propagated from ``verify`` if the
            forwarded declaration leaves *Charlie* a matched set below the
            floor. His :class:`~sih141.protocol.verify.VerificationAbort` is
            recorded in :attr:`aborts` first; :meth:`run` catches it.

        Notes
        -----
        Neither a rejection nor an abort at Bob blocks the call. A real Bob
        forwards only what he accepted, so the honest composite event is
        ``bob.accepted and charlie.accepted``; but Phase 3 needs Charlie's
        outcome on runs Bob rejected too, to measure both error rates of the
        pair rather than one, and on runs Bob could not score at all, because a
        declaration that starves one verifier almost always starves the other
        and the transcript should say so rather than stop at the first
        refusal. So the refusal is left to the transcript's derived properties
        instead of being baked in here.
        """
        if Party.BOB not in self._results and Party.BOB not in self._aborts:
            raise self._not_yet(
                "Bob has not run Phase C, so there is nothing for him to "
                "forward",
                "session.verify(Party.BOB)",
            )
        assert self._signature is not None  # implied by Bob's verdict existing
        # The hop itself is :meth:`forward`, which is idempotent: under the
        # after-forwarding ordering it has already run, and calling the seam a
        # second time would give an adversary two chances to substitute.
        self.forward()
        return self.verify(Party.CHARLIE)

    def _call_forwarder(self, signature: Signature) -> Signature:
        """Run the Bob-to-Charlie hop, building Bob's view only if it is wanted.

        Parameters
        ----------
        signature : Signature
            The declaration Bob received and scored.

        Returns
        -------
        Signature
            Whatever the seam returned, unchecked; :meth:`transfer` validates
            it.

        Notes
        -----
        The view is **Bob's**, because Bob owns this hop, and it is built here
        rather than kept on the session so that a forwarder which does not ask
        for one never causes it to exist. It carries his own matched count when
        he has one -- he has just verified, so he does -- because that is
        genuinely what he holds at this moment, and a recipient-flavoured attack
        that wants to decide *whether* to forge from how much evidence he
        matched should not have to recompute it. A refusal to score leaves the
        count out rather than reporting zero: he did not match nothing, he
        reached no verdict (:mod:`sih141.protocol.verify`).

        There is no route from here to Charlie's log.
        :class:`~sih141.protocol.records.RecipientView` is one party's holdings
        by construction and refuses to be built from a mixture
        (:ref:`sih141.protocol.records <recipient-view>`), which is the point of
        passing one rather than the mapping the signer seam used to get.
        """
        if not self._forwarder_wants_view:
            return self._forwarder(signature, self._scored_params)
        verdict = self._results.get(Party.BOB)
        view = RecipientView.for_party(
            Party.BOB,
            signature.message_bit,
            raw_records=self._raw_records,
            records=self._records,
            matched_count=None if verdict is None else verdict.matched_count,
        )
        return self._forwarder(signature, self._scored_params, view=view)

    # -- the whole run ------------------------------------------------------ #

    def run(self, message_bit: int) -> SessionTranscript:
        """Execute the entire protocol for one message bit and report.

        Equivalent to :meth:`distribute`, :meth:`sign`, :meth:`exchange_counts`,
        ``verify(Party.BOB)``, :meth:`transfer`, :meth:`transcript` -- in that
        order, which is the order the protocol fixes.

        A verifier who cannot score the declaration does **not** end the run.
        :exc:`~sih141.protocol.verify.MatchedSetTooSmall` is caught at each of
        the two Phase C steps and the refusal, already recorded by
        :meth:`verify`, is carried into
        :attr:`SessionTranscript.aborts`; the other verifier is still asked. So
        an attacker who starves the matched set -- a signer reading both raw
        logs can drive it to zero, see :ref:`two-log-signer` -- costs the
        harness a verdict, not a run, and cannot crash a verifier.

        Parameters
        ----------
        message_bit : int
            ``0`` or ``1``.

        Returns
        -------
        SessionTranscript
            The run, frozen and JSON-serialisable.
            :attr:`~SessionTranscript.is_complete` says whether both verifiers
            reached a verdict, :attr:`~SessionTranscript.aborted` whether either
            refused to score.

        Raises
        ------
        ValueError
            As the individual phases; in particular if the session has already
            been used. **Not** for a matched set too small to score: that is an
            outcome and is recorded, never raised out of here.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.session import QDSSession
        >>> params = ProtocolParams(key_length=24)
        >>> first = QDSSession(params, rng=np.random.default_rng(3)).run(0)
        >>> second = QDSSession(params, rng=np.random.default_rng(3)).run(0)
        >>> first == second
        True
        >>> first.transferable, first.aborted
        (True, False)
        """
        self.distribute()
        self.sign(message_bit)
        if self._count_exchange_timing == COUNTS_AFTER_FORWARDING:
            # The deployment ordering: Charlie has to be holding a declaration
            # before he can count against one, so the hop comes first and Bob's
            # verdict waits on it. See :data:`COUNTS_AFTER_FORWARDING`.
            self.forward()
        # Phase C', explicitly and in order: the recipients compare matched
        # counts before either of them reaches a verdict. verify() would trigger
        # it anyway, but the step is one classical message each way and belongs
        # in the list of phases rather than inside one of them.
        self.exchange_counts()
        # Both Phase C steps record their own refusal on the session before
        # raising, so catching MatchedSetTooSmall here loses nothing: it turns
        # "this verifier reached no verdict" from a lost run into a line in the
        # transcript. Only that one exception is caught -- a wiring error still
        # fails loudly, and the second verifier is still asked, because a
        # declaration that starves one usually starves both and the transcript
        # should say so rather than stop at the first refusal.
        try:
            self.verify(Party.BOB)
        except MatchedSetTooSmall:
            pass
        try:
            self.transfer()
        except MatchedSetTooSmall:
            pass
        return self.transcript()

    def transcript(self) -> SessionTranscript:
        """Freeze what has happened so far into a :class:`SessionTranscript`.

        Returns
        -------
        SessionTranscript
            The parameters, the declaration, all four classical logs, the
            verdicts reached so far and any refusals to score, in protocol
            order. Records are ordered by message bit and then by
            :data:`~sih141.protocol.params.VERIFIERS`; verdicts and refusals in
            the order they were reached.

        Raises
        ------
        ValueError
            If the session has not signed yet: before Phase B there is no
            declaration, and a transcript of a run with nothing to verify would
            be a record of nothing.

        Notes
        -----
        Callable on an unfinished run -- a transcript with one verdict, or
        none, is exactly what a Phase 3 experiment that abandons a run needs to
        report. :attr:`SessionTranscript.is_complete` says which it is.
        """
        if self._signature is None:
            raise self._not_yet(
                "nothing has been signed, so there is no run to report",
                "session.sign(message_bit)",
            )
        records = tuple(
            self._records[bit][party]
            for bit in MESSAGE_BITS
            for party in VERIFIERS
        )
        forwarded = self._forwarded
        return SessionTranscript(
            params=self._params,
            message_bit=self._signature.message_bit,
            signature=self._signature,
            records=records,
            results=tuple(self._results.values()),
            aborts=tuple(self._aborts.values()),
            pooled=self._pooled,
            # None whenever the hop was the identity, so an honest transcript
            # carries one declaration and compares equal across runs.
            forwarded_signature=(
                None
                if forwarded is None or forwarded == self._signature
                else forwarded
            ),
            run_id=self._run_id,
            # Ordered, so that two runs of one seed compare equal: the mapping
            # is keyed by (party, bit) and dictionary order would otherwise
            # follow whatever order the seam happened to return.
            check_logs=tuple(
                self._check_logs[key]
                for key in sorted(
                    self._check_logs, key=lambda item: (item[1], item[0].value)
                )
            ),
            channel=tuple(self._channel),
            signer_saw_recipient_logs=self._signer_sees_recipient_logs,
            count_exchange_timing=self._count_exchange_timing,
            # Sorted rather than in ledger order: the ledger is a set, and a
            # transcript whose field order depended on iteration order would
            # stop two runs of one seed comparing equal.
            spent_rounds=tuple(
                sorted(
                    (party.value, session_id, bit)
                    for party, ledger in self._ledgers.items()
                    for session_id, bit in ledger.spent_rounds()
                )
            ),
            replay_refusals=tuple(
                sorted(
                    (party.value, count)
                    for party, count in self._replay_refusals.items()
                )
            ),
        )

    # -- helpers ------------------------------------------------------------ #

    @staticmethod
    def _not_yet(problem: str, call: str) -> ValueError:
        """Build the out-of-order error, which always names the fix.

        Parameters
        ----------
        problem : str
            What is missing, phrased as a clause.
        call : str
            The call that would supply it.

        Returns
        -------
        ValueError
            To be raised by the caller.
        """
        return ValueError(
            f"the session is not far enough along: {problem}. The phases run "
            f"in order -- distribute, sign, verify(Party.BOB), transfer -- so "
            f"call {call} first, or run(message_bit) for all of them."
        )


def _check_result_against(
    result: VerificationResult,
    params: ProtocolParams,
    message_bit: int,
) -> None:
    """Check one verdict against the parameter set the transcript claims.

    :class:`~sih141.protocol.verify.VerificationResult` enforces only its own
    internal consistency -- ``accepted == (rate <= threshold)`` -- so a verdict
    carrying the *wrong party's* threshold is perfectly self-consistent and
    survives a JSON round trip unchallenged. Since
    :meth:`SessionTranscript.from_json` is the hand-off boundary for Phases 4 to
    6, that is exactly how a run Bob rejected comes back reporting
    ``transferable=True``: rewrite each verdict's ``threshold`` to ``s_v``,
    recompute ``accepted``, and nothing downstream objects. So the transcript
    re-derives the threshold from ``params`` and the party and insists they
    agree. It is the same confusion :func:`sih141.protocol.verify.verify_all`
    guards against at the live boundary, closed at the persistence one.

    Parameters
    ----------
    result : VerificationResult
        One verdict.
    params : ProtocolParams
        The parameter set the transcript is tagged with.
    message_bit : int
        The bit the transcript is tagged with.

    Raises
    ------
    ValueError
        If the verdict's threshold, key length or message bit disagrees with
        the transcript's own parameters.
    """
    expected_threshold = params.threshold_for(result.party)
    if result.threshold != expected_threshold:
        raise ValueError(
            f"{result.party.value}'s verdict carries threshold "
            f"{result.threshold!r} but this transcript's parameters put his cut "
            f"at {expected_threshold!r} (s_a={params.s_a!r}, "
            f"s_v={params.s_v!r}). The threshold is a property of *whose* log "
            f"was scored, never a free field: a verdict holding the other "
            f"verifier's cut is internally consistent and still wrong, and it "
            f"would make this transcript report transferability for a run the "
            f"verifier rejected."
        )
    if result.key_length != params.key_length:
        raise ValueError(
            f"{result.party.value}'s verdict reports key_length "
            f"{result.key_length} but this transcript's parameters say "
            f"{params.key_length}. The verdict's discarded-position count, and "
            f"every Phase 4 statistic derived from it, would be computed "
            f"against the wrong denominator."
        )
    if result.message_bit != message_bit:
        raise ValueError(
            f"{result.party.value}'s verdict is for message bit "
            f"{result.message_bit} but this transcript is tagged with bit "
            f"{message_bit}. The bit selects which distribution was scored."
        )


def _check_abort_against(
    abort: VerificationAbort,
    params: ProtocolParams,
    message_bit: int,
) -> None:
    """Check one refusal to score against the parameters the transcript claims.

    The same persistence-boundary argument as :func:`_check_result_against`.
    :class:`~sih141.protocol.verify.VerificationAbort` enforces only its own
    internal consistency, so a refusal quoting another run's key length -- or a
    floor that was never this parameter set's -- survives a JSON round trip
    unchallenged and would put a fabricated shortfall in front of a Phase 5
    reader. The floor is re-derived from ``params`` and insisted on.

    Parameters
    ----------
    abort : VerificationAbort
        One refusal.
    params : ProtocolParams
        The parameter set the transcript is tagged with.
    message_bit : int
        The bit the transcript is tagged with.

    Raises
    ------
    ValueError
        If the refusal's key length, expected matched count, floor or message
        bit disagrees with the transcript's own parameters.
    """
    if abort.key_length != params.key_length:
        raise ValueError(
            f"{abort.party.value}'s refusal reports key_length "
            f"{abort.key_length} but this transcript's parameters say "
            f"{params.key_length}. The shortfall it records would be measured "
            f"against the wrong number of positions."
        )
    expected_floor = minimum_matched_count(params)
    if abort.minimum_matched != expected_floor:
        raise ValueError(
            f"{abort.party.value}'s refusal quotes a matched-count floor of "
            f"{abort.minimum_matched} but this transcript's parameters put it "
            f"at {expected_floor} (L={params.key_length}, "
            f"|B|={len(params.bases)}). The floor is derived from the "
            f"parameter set, never a free field: a refusal carrying a floor "
            f"nobody applied would make a scored run look starved, or a "
            f"starved one look scored."
        )
    if abort.expected_matched != params.expected_matched:
        raise ValueError(
            f"{abort.party.value}'s refusal reports an honest mean of "
            f"{abort.expected_matched!r} but this transcript's parameters give "
            f"L/|B| = {params.expected_matched!r}. That number is what makes "
            f"the shortfall legible, so it has to be this run's."
        )
    if abort.message_bit != message_bit:
        raise ValueError(
            f"{abort.party.value}'s refusal is for message bit "
            f"{abort.message_bit} but this transcript is tagged with bit "
            f"{message_bit}. The bit selects which distribution was scored."
        )


def _check_pooled_against(
    pooled: PooledMatchedCounts,
    params: ProtocolParams,
    message_bit: int,
) -> None:
    """Check one count exchange against the parameters the transcript claims.

    The same persistence-boundary argument as :func:`_check_result_against` and
    :func:`_check_abort_against`.
    :class:`~sih141.protocol.tally.PooledMatchedCounts` enforces only its own
    internal consistency, so an exchange quoting floors nobody applied survives
    a JSON round trip unchallenged -- and floors are exactly the field an
    editor would reach for to make a starved run look scored. Both are
    re-derived from ``params`` and insisted on.

    Parameters
    ----------
    pooled : PooledMatchedCounts
        The recorded exchange.
    params : ProtocolParams
        The parameter set the transcript is tagged with.
    message_bit : int
        The bit the transcript is tagged with.

    Raises
    ------
    ValueError
        If the exchange's key length, either floor, or its message bit
        disagrees with the transcript's own parameters.
    """
    if pooled.key_length != params.key_length:
        raise ValueError(
            f"the recorded count exchange reports key_length "
            f"{pooled.key_length} but this transcript's parameters say "
            f"{params.key_length}. Both floors are derived from the key "
            f"length, so the two cannot be from the same run."
        )
    for name, recorded, expected in (
        (
            "per-verifier",
            pooled.minimum_matched,
            minimum_matched_count(params),
        ),
        (
            "pooled",
            pooled.minimum_pooled,
            minimum_pooled_matched_count(params),
        ),
    ):
        if recorded != expected:
            raise ValueError(
                f"the recorded count exchange quotes a {name} matched-count "
                f"floor of {recorded} but this transcript's parameters put it "
                f"at {expected} (L={params.key_length}, "
                f"|B|={len(params.bases)}). A floor is derived from the "
                f"parameter set, never a free field: an exchange carrying a "
                f"floor nobody applied would make a run that failed the rule "
                f"look like one that passed it."
            )
    if pooled.message_bit != message_bit:
        raise ValueError(
            f"the recorded count exchange is for message bit "
            f"{pooled.message_bit} but this transcript is tagged with bit "
            f"{message_bit}. The bit selects which distribution was counted."
        )


def forwarder_wants_view(forwarder: Forwarder) -> bool:
    """Return ``True`` when ``forwarder`` *requires* a keyword-only ``view``.

    Public because it is part of the seam contract rather than an implementation
    detail: a Phase 3 probe that exercises a ``forwarder`` standalone has to call
    it the way the session would, and answering "which shape is this one?" by
    reading the private spelling of this function is how two modules ended up
    coupled to it (:func:`sih141.attacks.isolation.forwarder_probe`).

    The same question :func:`~sih141.protocol.distribute.accepts_context` asks
    of a ``resource_factory``, and for the same reason: "can it be called
    without?", not "can it accept one?". A forwarder that can be called as
    ``forwarder(signature, params)`` is called that way, so :func:`honest_forwarder`
    -- which declares ``view=None`` in order to have the full shape -- does not
    cause a :class:`~sih141.protocol.records.RecipientView` to be built on every
    honest run, and neither does any forwarder written before the parameter
    existed. Only ``*, view`` with no default asks for the evidence, which makes
    asking a deliberate act.

    Parameters
    ----------
    forwarder : Forwarder
        The resolved seam.

    Returns
    -------
    bool
        ``True`` if it must be given a ``view``, ``False`` if it can be called
        with the declaration and the parameters alone.

    Raises
    ------
    TypeError
        If the callable accepts neither shape. Caught at construction, because
        a session that failed here would already have teleported two keys.

    Notes
    -----
    A callable whose signature :mod:`inspect` cannot read -- some
    C-implemented ones -- is treated as not wanting a view, which is the
    historical shape and the only one such a callable can have here.
    """
    try:
        signature = inspect.signature(forwarder)
    except (TypeError, ValueError):
        return False
    probe = object()
    try:
        signature.bind(probe, probe)
    except TypeError:
        pass
    else:
        return False
    try:
        signature.bind(probe, probe, view=probe)
    except TypeError:
        raise TypeError(
            f"forwarder must be callable either as forwarder(signature, "
            f"params) or as forwarder(signature, params, *, view), but "
            f"{forwarder!r} accepts neither: its signature is {signature}. The "
            f"view is the forwarding recipient's own RecipientView -- his two "
            f"logs and his matched count, and nothing of the counterpart's; a "
            f"forwarder that does not want it should take two arguments."
        ) from None
    return True


_forwarder_wants_view = forwarder_wants_view
"""Deprecated private alias of :func:`forwarder_wants_view`.

Kept because it was imported by name before the public spelling existed. New
code should use the public name.
"""


def _check_sample_against(
    sample: ChannelSample,
    published: Mapping[tuple[Party, int], CheckLog],
    params: ProtocolParams,
) -> None:
    """Check one channel sample really describes a check round of this run.

    **The load-bearing check of the channel-monitor seam**, and the reason it is
    enforced at the persistence boundary rather than trusted from the live one.
    A sample says "here is the pair your link was given at position ``i``"; if
    ``i`` were a key position, that sentence would be a per-position statement
    about the very rounds the signature is made of, and the estimate would stop
    being a sample of anything. The live path cannot produce such a sample --
    :class:`_ChannelTap` records only where the plan says -- but a transcript is
    a file, and a file can say whatever it was written to say.

    The comparison is against the run's own published
    :class:`~sih141.protocol.checkrounds.CheckLog`, which is the only thing in
    the transcript that knows which positions were check rounds. A run whose
    distributor seam returned no log at all cannot be checked this way, and is
    not refused: the position is checked for range and the sample stands, which
    is the honest reading of "the channel was tapped but nothing was published".

    Parameters
    ----------
    sample : ChannelSample
        One resource summary.
    published : mapping
        The transcript's check logs, keyed by ``(party, message_bit)``.
    params : ProtocolParams
        The transcript's **unsifted** parameter set: check positions are indexed
        in the full ``0 .. L-1`` numbering, which is exactly the numbering the
        sifted set no longer has.

    Raises
    ------
    ValueError
        If the position is outside the run, if it is not one the matching log
        recorded, or if the sample's role disagrees with the arm the log
        recorded it in.
    """
    if sample.position >= params.key_length:
        raise ValueError(
            f"a channel sample sits at position {sample.position} but this "
            f"run has {params.key_length} positions. Check positions are "
            f"indexed in the unsifted key, 0 .. L-1."
        )
    log = published.get((sample.party, sample.message_bit))
    if log is None:
        return
    if sample.position not in log.positions:
        raise ValueError(
            f"a channel sample claims position {sample.position} of "
            f"{sample.party.value}'s message bit {sample.message_bit}, but "
            f"that position is not a check round of this run: the published "
            f"log recorded {len(log.positions)} of them and this is not one. "
            f"Only check positions may be published per position -- a key "
            f"position's channel is precisely what sampling exists not to "
            f"report."
        )
    arm = (
        CheckRole.QBER
        if sample.position in {entry.position for entry in log.qber}
        else CheckRole.CHSH
    )
    if sample.role is not arm:
        raise ValueError(
            f"a channel sample at position {sample.position} of "
            f"{sample.party.value}'s message bit {sample.message_bit} is "
            f"tagged {sample.role.value!r}, but the published log recorded that "
            f"round in the {arm.value!r} arm. The role says which statistic the "
            f"round feeds, so a mismatch would file a pair's diagnostics under "
            f"the wrong estimator."
        )


def _check_seam(seam: Any, name: str, expected: str) -> None:
    """Reject a non-callable seam at construction rather than mid-run.

    Parameters
    ----------
    seam : Any
        The injected callable, or ``None`` for the honest default.
    name : str
        The parameter name, quoted in the message.
    expected : str
        A description of what the seam should be, quoted in the message.

    Returns
    -------
    None

    Raises
    ------
    TypeError
        If ``seam`` is neither ``None`` nor callable. Caught here because a
        session that fails only once it reaches the seam would have teleported
        a whole key first.
    """
    if seam is not None and not callable(seam):
        raise TypeError(
            f"{name} must be None or {expected}, got "
            f"{type(seam).__name__}. See the Phase 3 seams section of "
            f"sih141.protocol.session for what each seam replaces."
        )
