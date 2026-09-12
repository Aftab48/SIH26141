/* render.js -- the panels.
 *
 * Every panel below is written against ONE rule: the string it puts on the
 * screen either came out of the API as a string, or came out of `format.js`
 * applied to a value the API sent. There is no third source. In particular
 * there is no arithmetic in this file at all -- no `Math.`, no `/`, no `*`, no
 * numeric `+` -- and `tests/test_web_frontend.py` greps for them, so the rule
 * is enforced rather than promised.
 *
 * The eight things the screen has to get right, and where each one is:
 *
 *   1  an abort is a THIRD state          `outcomeToken`, `verdictStrip`,
 *                                         `noVerdictBanner`
 *   2  proven vs measured                 `proven` / `measured` chips, used
 *                                         nowhere interchangeably
 *   3  the null is noiseless by default   `nullBanner`
 *   4  (AUTH) is a stated assumption      `attributionPanel`, `groundTruth`
 *   5  a withheld family is not a pass    `channelPanel`, `withheldPanel`
 *   6  never pool over the timing         `groupingPanel`
 *   7  demo scale proves no transferability
 *                                         `transferabilityPanel`
 *   8  publish false_positive_bound       `boundsPanel`
 */

const Render = (function () {
  "use strict";

  /* ---------------------------------------------------------------------- *
   * DOM helpers
   * ---------------------------------------------------------------------- */

  /**
   * Build an element. Text is always set with `textContent`, never as markup:
   * an API string is data, and data does not get to write HTML.
   *
   * @param {string} tag
   * @param {Object} [opts] `class`, `text`, `title`, `attrs`.
   * @param {Array<Node>} [children]
   * @returns {HTMLElement}
   */
  function h(tag, opts, children) {
    const node = document.createElement(tag);
    const options = opts || {};
    if (options.class) {
      node.className = options.class;
    }
    if (options.text !== undefined && options.text !== null) {
      node.textContent = options.text;
    }
    if (options.attrs) {
      Object.keys(options.attrs).forEach(function (key) {
        node.setAttribute(key, options.attrs[key]);
      });
    }
    (children || []).forEach(function (child) {
      if (child) {
        node.appendChild(child);
      }
    });
    return node;
  }

  /**
   * A titled panel.
   *
   * @param {string} title
   * @param {string|null} hint
   * @param {Array<Node>} children
   * @returns {HTMLElement}
   */
  function panel(title, hint, children) {
    const heading = h("h2", { text: title });
    if (hint) {
      heading.appendChild(h("span", { class: "hint", text: hint }));
    }
    return h("section", { class: "panel" }, [
      heading,
      h("div", { class: "panel-body" }, children),
    ]);
  }

  /**
   * The visible marker that stands where a panel would have been.
   *
   * @param {Array<string>} paths
   * @returns {HTMLElement}
   */
  function notSupplied(paths) {
    return h("div", { class: "missing" }, [
      h("div", {
        text: "THE API DID NOT SUPPLY THIS. Nothing is shown in its place.",
      }),
      h("div", { text: paths.join("  ·  ") }),
      h("div", {
        text:
          "Deriving it in the browser would put an untested number on the " +
          "screen beside tested ones, so the frontend refuses (D8).",
      }),
    ]);
  }

  /* ---------------------------------------------------------------------- *
   * The four states, and the two kinds of number
   * ---------------------------------------------------------------------- */

  const STATE = {
    clean: { css: "is-clean", glyph: "●" },
    detected: { css: "is-detected", glyph: "▲" },
    noverdict: { css: "is-noverdict", glyph: "◇" },
    withheld: { css: "is-withheld", glyph: "⊘" },
    neutral: { css: "is-neutral", glyph: "○" },
    // Attribution only. Kept off the verdict palette on purpose: see the note
    // beside `.is-named` in app.css.
    named: { css: "is-named", glyph: "◆" },
    ruledout: { css: "is-ruledout", glyph: "⊗" },
  };

  /**
   * A state token: hue, glyph, border style and a word, all four at once.
   *
   * @param {string} kind A key of `STATE`.
   * @param {string} label
   * @returns {HTMLElement}
   */
  function token(kind, label) {
    const spec = STATE[kind] || STATE.neutral;
    return h("span", { class: `state ${spec.css}` }, [
      h("span", { class: "glyph", text: spec.glyph, attrs: {
        "aria-hidden": "true",
      } }),
      h("span", { text: label }),
    ]);
  }

  /** Which state a `RunOutcome` string is. The four-valued answer, kept four. */
  const OUTCOME_STATE = {
    accepted: { kind: "clean", label: "ACCEPTED" },
    rejected: { kind: "detected", label: "REJECTED" },
    "refused-to-score": { kind: "noverdict", label: "NO VERDICT" },
    "not-asked": { kind: "withheld", label: "NOT ASKED" },
  };

  /**
   * Render one verifier's outcome. Never a boolean, never a tick.
   *
   * @param {string|null|undefined} outcome
   * @returns {HTMLElement}
   */
  function outcomeToken(outcome) {
    const spec = OUTCOME_STATE[outcome];
    if (!spec) {
      return token("neutral", "OUTCOME NOT SUPPLIED");
    }
    return token(spec.kind, spec.label);
  }

  /**
   * A PROVEN number: derived from a stated null by a named inequality.
   *
   * @param {string} value Pre-formatted.
   * @param {string} qualifier What it is a bound on.
   * @returns {HTMLElement}
   */
  function proven(value, qualifier) {
    return h("span", { class: "num num-proven" }, [
      h("span", { class: "kind", text: "⊢ proven" }),
      h("span", { class: "value", text: value }),
      qualifier ? h("span", { class: "qual", text: qualifier }) : null,
    ]);
  }

  /**
   * A MEASURED number: counted over runs, and useless without its sample size.
   *
   * @param {string} value Pre-formatted.
   * @param {string} sample The sample size, in words.
   * @returns {HTMLElement}
   */
  function measured(value, sample) {
    return h("span", { class: "num num-measured" }, [
      h("span", { class: "kind", text: "measured" }),
      h("span", { class: "value", text: value }),
      sample ? h("span", { class: "qual", text: sample }) : null,
    ]);
  }

  /**
   * A number that is neither: an observation off this one transcript.
   *
   * @param {string} value Pre-formatted.
   * @param {string} [qualifier]
   * @returns {HTMLElement}
   */
  function plain(value, qualifier) {
    return h("span", { class: "num num-plain" }, [
      h("span", { class: "value", text: value }),
      qualifier ? h("span", { class: "qual", text: qualifier }) : null,
    ]);
  }

  /**
   * Return the first supplied value of `name` among several objects.
   *
   * Selection, never derivation: it looks in each object in turn and returns
   * the value it finds, or `undefined` so the caller can render "not supplied"
   * rather than a zero.
   *
   * It exists because `/api/defaults` grew its `bounds` block in two places
   * while the two halves of Phase 6 were being written in parallel -- some
   * figures nested under `headline`/`demo`, the same figures flat beside them.
   * Reading both is what keeps the screen from blanking a panel over a field
   * that moved, and it costs nothing: whichever object holds the number, the
   * number is still the API's.
   *
   * @param {Array<Object|null|undefined>} objects Most specific first.
   * @param {string} name
   * @returns {*}
   */
  function pick(objects, name) {
    let found;
    objects.forEach(function (object) {
      if (
        found === undefined &&
        object &&
        typeof object === "object" &&
        Object.prototype.hasOwnProperty.call(object, name)
      ) {
        found = object[name];
      }
    });
    return found;
  }

  /**
   * A definition list.
   *
   * @param {Array<Array>} rows `[term, value-node-or-string]` pairs.
   * @param {string} [cls]
   * @returns {HTMLElement}
   */
  function kv(rows, cls) {
    const list = h("dl", { class: cls || "kv" });
    rows.forEach(function (row) {
      if (!row) {
        return;
      }
      list.appendChild(h("dt", { text: row[0] }));
      const value = h("dd", {});
      if (typeof row[1] === "string") {
        value.textContent = row[1];
      } else if (row[1]) {
        value.appendChild(row[1]);
      }
      list.appendChild(value);
    });
    return list;
  }

  /**
   * One row of a two-column comparison table.
   *
   * @param {string} term
   * @param {Node} left
   * @param {Node} right
   * @returns {HTMLElement}
   */
  function compareRow(term, left, right) {
    return h("tr", {}, [
      h("td", { text: term }),
      h("td", { class: "numeric" }, [left]),
      h("td", { class: "numeric" }, [right]),
    ]);
  }

  /**
   * A banner.
   *
   * @param {string} tone `alarm`, `caution`, `info`, `abort`.
   * @param {string} glyph
   * @param {string} heading
   * @param {Array<string>} paragraphs
   * @returns {HTMLElement}
   */
  function banner(tone, glyph, heading, paragraphs) {
    const body = h("div", { class: "body" }, [h("h3", { text: heading })]);
    paragraphs.forEach(function (line) {
      if (line) {
        body.appendChild(h("p", { text: line }));
      }
    });
    return h("div", { class: `banner ${tone}` }, [
      h("span", { class: "glyph", text: glyph, attrs: { "aria-hidden": "true" } }),
      body,
    ]);
  }

  /* ---------------------------------------------------------------------- *
   * 1. The verdict strip
   * ---------------------------------------------------------------------- */

  /**
   * The headline: what the detector said, what each verifier did, side by side.
   *
   * They are two different questions and they are never merged. A flag says the
   * run departed from a stated null; the verifiers say whether the signature
   * was acceptable. A run can be both detected and denied -- recipient forgery
   * is exactly that -- so a single three-way headline would have to throw one
   * of the two away.
   *
   * @param {Object} payload A `POST /api/run` response.
   * @returns {HTMLElement}
   */
  function verdictStrip(payload) {
    const detection = payload.detection;
    const run = payload.run;
    const detected = detection.detected;
    // The headline count comes from Python. `detection.signals.length` would
    // be a sum taken in the browser, and D8 does not carve out an exception for
    // sums that feel small; the detector's own summary already opens with
    // "detect: 2 signal(s) at eps = 1.000e-09", so that line is quoted instead.
    const headlineLine = String(detection.summary || "").split("\n")[0];

    const detectorBox = h(
      "div",
      { class: `verdict ${detected ? "is-detected" : "is-clean"}` },
      [
        h("div", { class: "headline" }, [
          h("span", {
            class: "glyph",
            text: detected ? STATE.detected.glyph : STATE.clean.glyph,
            attrs: { "aria-hidden": "true" },
          }),
          h("span", { text: detected ? "DETECTED" : "NOTHING FIRED" }),
        ]),
        h("div", { class: "sub" }, [
          h("code", { text: headlineLine }),
        ]),
        h("div", { class: "sub" }, [
          h("span", {
            text: detected
              ? "At least one derived threshold was crossed. This is a " +
                "departure from a stated null, not a verdict on the signature."
              : "No derived threshold was crossed at this budget. A quiet " +
                "detector is not a proof that nothing happened: there is no " +
                "false-negative bound and this project derives none.",
          }),
        ]),
        h("div", {}, [
          proven(
            Fmt.exp(detection.false_positive_bound),
            "P(any signal | honest run)"
          ),
        ]),
      ]
    );

    const outcomes = detection.outcomes || {};
    const notScored = detection.not_scored || [];
    const verifierRows = h("div", { class: "panel-body" });
    (run.verifiers || []).forEach(function (verifier) {
      const outcome = outcomes[verifier.party];
      const row = h("div", { class: "legend" }, [
        h("strong", { text: verifier.party }),
        outcomeToken(outcome),
      ]);
      if (verifier.scored === false) {
        row.appendChild(
          h("span", {
            class: "note",
            text:
              "no matched count, no mismatch count, no rate: he was denied " +
              "the evidence, so there is nothing to score and nothing to plot.",
          })
        );
      } else {
        row.appendChild(
          plain(
            `|M| = ${Fmt.count(verifier.matched)} / ${Fmt.count(
              verifier.matched_trials
            )}`,
            "matched"
          )
        );
        row.appendChild(
          plain(`e = ${Fmt.count(verifier.mismatches)}`, "mismatches")
        );
        row.appendChild(plain(Fmt.rate(verifier.rate), "rate"));
      }
      verifierRows.appendChild(row);
    });
    if (notScored.length > 0) {
      verifierRows.appendChild(
        h("p", {
          class: "note",
          text:
            `reached no verdict: ${notScored.join(", ")}. A no-verdict is ` +
            "never counted as a rejection, never counted as a detection, and " +
            "never folded into a rate.",
        })
      );
    }

    const verifierBox = h("section", { class: "panel" }, [
      h("h2", { text: "Verifiers" }, [
        h("span", {
          class: "hint",
          text: "four-valued: accepted / rejected / no verdict / not asked",
        }),
      ]),
      verifierRows,
    ]);

    return h("div", { class: "grid-2" }, [
      h("section", { class: "panel" }, [
        h("h2", { text: "Detector" }, [
          h("span", { class: "hint", text: "did a derived threshold fire?" }),
        ]),
        h("div", { class: "panel-body" }, [detectorBox]),
      ]),
      verifierBox,
    ]);
  }

  /**
   * The third-state banner: shown whenever any verifier reached no verdict.
   *
   * @param {Object} payload
   * @returns {HTMLElement|null}
   */
  function noVerdictBanner(payload) {
    const notScored = payload.detection.not_scored || [];
    if (notScored.length === 0) {
      return null;
    }
    const aborts = (payload.run && payload.run.aborts) || {};
    const reasons = aborts.by_party || {};
    const named = Object.keys(reasons).map(function (party) {
      return `${party}: ${reasons[party]}`;
    });
    return banner(
      "abort",
      STATE.noverdict.glyph,
      `No verdict: ${notScored.join(", ")}`,
      [
        "This is a THIRD STATE. It is not an acceptance and it is not a " +
          "rejection: the verifier was asked, was denied the evidence a " +
          "verdict needs, and learned nothing at all about the signature.",
        named.length > 0
          ? `reason on the transcript: ${named.join("; ")}`
          : null,
        "It must not be counted as a detection, must not be counted as a " +
          "miss, and must not appear in the denominator of any rate.",
      ]
    );
  }

  /* ---------------------------------------------------------------------- *
   * 3. The null
   * ---------------------------------------------------------------------- */

  /**
   * The two null-setting controls, named exactly as the request field is.
   *
   * The API supplies both names in `run.nulls`, so the sentence that tells an
   * operator what to set cannot drift from the field they have to set. Where
   * the API does not supply them the fallback is the contract's own spelling.
   *
   * @param {Object} nulls `run.nulls`, or an empty object.
   * @returns {Object} `{rate, channel}` field names.
   */
  function nullFields(nulls) {
    return {
      rate: (nulls && nulls.rate_null_field) || "channel_error_rate",
      channel:
        (nulls && nulls.channel_null_field) || "tolerated_depolarising",
    };
  }

  /**
   * Say which nulls the run was scored against. THERE ARE TWO OF THEM.
   *
   * This is the dashboard's worst failure mode: an honest run over a noisy
   * link departs from a null nobody meant to state and is correctly reported
   * as detected, so the baseline lights up red in front of an audience. The
   * banner is what turns that from a lie into a lesson, and it only works if
   * the instruction it gives is one that actually clears the run.
   *
   * `detect()` takes TWO nulls, `channel_error_rate` for the rate family and
   * `tolerated_depolarising` for the channel family, and both default to a
   * perfect link. `Detection.null_is_noiseless` is the RATE family's flag and
   * nothing more. Keying this banner off it alone told an operator to set "the
   * link's true rate", singular, and then congratulated them with a calm blue
   * INFO banner while the channel family's null was still wrong about the wire:
   * measured over twelve seeds at L = 192 with a link at the design noise
   * level, that state is 12/12 DETECTED with `honest` RULED OUT and
   * `channel-manipulation` NAMED. So there are three states here, not two, and
   * the middle one is a warning.
   *
   * @param {Object} payload
   * @param {Object} context `{defaults, attacks, constants}`. Any of them may
   *   be missing; the panel that needed one says so rather than inventing it.
   * @returns {Array<Node>}
   */
  function nullBanners(payload, context) {
    const detection = payload.detection;
    const nulls = (payload.run && payload.run.nulls) || null;
    const field = nullFields(nulls);
    const out = [];

    // Every branch below is chosen by a flag PYTHON computed
    // (`sih141.web.payload.nulls_stated`). Nothing here compares a null to
    // zero: that comparison decides what an operator is told to do, and a
    // decision that changes the screen is not a thing the browser gets to make
    // (D8). Where the API supplies no `run.nulls` the detector's own rate-family
    // flag is used and the banner says that is all it knows.
    const bothDefault = nulls
      ? nulls.both_are_default === true
      : detection.null_is_noiseless === true;
    const onlyOneStated = nulls
      ? nulls.both_are_default === false && nulls.both_are_stated === false
      : false;

    // The harness knows whether the nulls actually matched the link, and the
    // detector does not. Saying so turns a standing caution into a statement
    // about THIS run -- and it is the harness's sentence, quoted, not an
    // inference drawn from the transcript. It belongs on every branch: "both
    // nulls stated" is not the same claim as "both nulls match the wire", and
    // a run can be in one without the other.
    const truthLink = (payload.ground_truth || {}).link;
    let harness = null;
    if (truthLink && truthLink.nulls_match_link === true) {
      harness =
        "On this run the harness confirms the nulls DO match the link, so a " +
        "wrongly stated null is not the explanation for anything that fired. " +
        "That is the harness's knowledge and not the detector's.";
    } else if (truthLink && truthLink.nulls_match_link === false) {
      harness = (payload.ground_truth || {}).adversary_present
        ? "On this run the harness confirms the nulls do not match the link " +
          "AND that an adversary is mounted on it. Both readings fit the same " +
          "transcript; the detector cannot separate them, and this screen " +
          "does not pretend it can."
        : "On this run the harness confirms the nulls do NOT match the link, " +
          "and that no adversary is mounted. What fired is a null being wrong " +
          "about the wire.";
    }

    if (onlyOneStated) {
      const rateStated = nulls.rate_null_is_default === false;
      const paragraphs = [
        "ONE OF THE TWO NULLS IS STILL THE DEFAULT. detect() is told two, " +
          "and both default to a perfect link: " +
          `${field.rate} is the null the RATE family reads the verifiers' ` +
          `mismatch counts against, and ${field.channel} is the null the ` +
          "CHANNEL family reads the published check rounds against.",
        rateStated
          ? `${field.rate} = ${Fmt.rate(nulls.channel_error_rate)} was ` +
            `supplied. ${field.channel} is still ` +
            `${Fmt.rate(nulls.tolerated_depolarising)}, which claims an ideal ` +
            "entanglement resource, so the channel family is still scoring " +
            "this run against a link nobody has."
          : `${field.channel} = ` +
            `${Fmt.rate(nulls.tolerated_depolarising)} was supplied. ` +
            `${field.rate} is still ` +
            `${Fmt.rate(nulls.channel_error_rate)}, which claims a matched ` +
            "position never disagrees, so the rate family is still scoring " +
            "this run against a link nobody has.",
        "They are two parameterisations of the same physics and neither is " +
          "converted into the other: doing that silently would state a null " +
          "the operator did not ask for. Set BOTH in the controls, or read " +
          "what fired as a departure from the half that was left at its " +
          "default. Neither is ever inferred from the transcript.",
        nulls.note || "",
      ];
      if (detection.detected === true) {
        paragraphs.unshift(
          "THIS RUN FIRED WITH ONLY ONE NULL STATED. That is exactly the " +
            "state in which an HONEST run is reported as detected with an " +
            "adversary named. Read the ground-truth box before reading this " +
            "as an attack."
        );
      }
      paragraphs.push(harness);
      out.push(
        banner(
          detection.detected === true ? "alarm" : "caution",
          "⚠",
          "Only one of the two nulls is stated",
          paragraphs
        )
      );
    } else if (bothDefault) {
      const paragraphs = [
        `detect() was given ${field.rate} = 0.0 AND ${field.channel} = 0.0, ` +
          "which are its defaults and are TWO separate claims about a perfect " +
          "link: that a matched position never disagrees, and that the " +
          "entanglement resource is ideal.",
        "An honest run over a noisy link departs from both and is reported as " +
          "detected. The arithmetic is right; the row is still a false claim " +
          "if nobody says which nulls it was scored against. Set BOTH " +
          `controls: ${field.rate} to the link's true matched-position error ` +
          `rate and ${field.channel} to its Werner strength, to score it ` +
          "against the link instead. Setting only one does not clear the run. " +
          // The reason this clause used to give -- "because at
          // check_fraction = 0 the transcript carries no estimate of either"
          // -- is the API's sentence about ONE run, hardcoded here and printed
          // on every run: at check_fraction = 0.25 the transcript does carry
          // an estimate, and the banner was giving a false reason for a true
          // design. The design holds on every run; only the reason was local
          // to one, so the reason is gone and the statement stays.
          "Neither is ever inferred from the transcript.",
      ];
      if (detection.detected === true) {
        paragraphs.unshift(
          "THIS RUN FIRED, AND IT WAS SCORED AGAINST BOTH NOISELESS NULLS. " +
            "Read the ground-truth box before reading this as an adversary."
        );
      }
      if (!nulls) {
        paragraphs.push(
          "The API did not supply run.nulls on this response, so the only " +
            "flag available here is the RATE family's " +
            "(Detection.null_is_noiseless). The channel family's null is not " +
            "reported and this banner cannot speak for it."
        );
      }
      paragraphs.push(harness);
      out.push(
        banner(
          detection.detected === true ? "alarm" : "caution",
          "⚠",
          // Without `run.nulls` this branch is standing on the rate family's
          // flag alone, and the heading says only what that flag knows. A
          // heading is read on its own; it does not get to claim the half of
          // the state the response did not supply.
          nulls
            ? "Both nulls are noiseless"
            : "The rate family's null is noiseless",
          paragraphs
        )
      );
    } else {
      // The heading says what is TRUE of this branch -- that both nulls were
      // stated -- and not that they are the right ones. "Both nulls carry the
      // link" would be a claim about the wire, and the operator can state two
      // nulls that describe a link nobody has: type an honest link's numbers
      // on a run with Eve on the resource seam and the heading would assert
      // she is not there. Whether the nulls MATCH is the harness's sentence,
      // below, and only the harness knows it.
      //
      // And without `run.nulls` this branch knows even less than that. It is
      // reached on `detection.null_is_noiseless === false`, which is the RATE
      // family's flag alone: the channel family's null was not reported, so
      // "both were stated" is a claim about a half of the state that never
      // arrived, and printing `tolerated_depolarising = n/a` inside the
      // sentence that makes the claim does not withdraw it. Same treatment as
      // the sibling branch above -- the heading says what the one flag knows,
      // and a paragraph says the response is why.
      const paragraphs = [
        nulls
          ? `The rate family's mismatch members were scored against ` +
            `${field.rate} = ${Fmt.rate(detection.channel_error_rate)} and ` +
            `the channel family's check rounds against ${field.channel} = ` +
            `${Fmt.rate(nulls.tolerated_depolarising)}. Both were ` +
            `supplied by the operator rather than read off the transcript, ` +
            `and neither was inferred from it.`
          : `The rate family's mismatch members were scored against ` +
            `${field.rate} = ${Fmt.rate(detection.channel_error_rate)}, ` +
            `which was supplied by the operator rather than read off the ` +
            `transcript. What ${field.channel} was set to is not reported ` +
            `on this response, so nothing here says what the channel ` +
            `family's check rounds were scored against.`,
      ];
      if (!nulls) {
        paragraphs.push(
          "The API did not supply run.nulls on this response, so the only " +
            "flag available here is the RATE family's " +
            "(Detection.null_is_noiseless). The channel family's null is not " +
            "reported and this banner cannot speak for it."
        );
      }
      // A standing statement about the design rather than about this run, so
      // it is true on both sides of the branch above.
      paragraphs.push(
        "Stating both is necessary for an honest run over a noisy link to " +
          "come back quiet, and it is not sufficient: these are the laws " +
          "the run was SCORED against, and whether they are the laws the " +
          "wire obeyed is a separate question that only the harness can " +
          "answer. Stating either one alone does not reach even this far, " +
          "the family whose null is still the default goes on scoring the " +
          "run against a link nobody has."
      );
      paragraphs.push(harness);
      out.push(
        banner(
          "info",
          "ℹ",
          nulls
            ? "Both nulls were stated by the operator"
            : "The rate family's null is not noiseless",
          paragraphs
        )
      );
    }

    if (detection.bound_is_unconditional === false) {
      out.push(
        banner("caution", "⚠", "The published bound is conditional", [
          "A positive channel_error_rate made the rate family's mismatch " +
            "members conditional on this run's matched counts. The sum is " +
            "still a correct bound, but on P(fire | the matched counts).",
          `What remains unconditionally true is the budget itself, ` +
            `eps = ${Fmt.exp(detection.eps)}.`,
        ])
      );
    }

    // The API's own calibration when it publishes one; the shipped constant
    // otherwise. Both are Phase 4 measurements and both are pinned by a test.
    const calibration = pick(
      [context.defaults, context.constants],
      "noise_null_calibration"
    );
    if (calibration) {
      out.push(noiseCalibration(calibration));
    }
    return out;
  }

  /**
   * The measured cost of the noiseless null, with its sample size on it.
   *
   * TWO sentences follow the table and both are the API's, verbatim.
   * `with_true_rate_passed` says what the table becomes when the nulls are
   * stated; `second_null_note` says that there are TWO of them and what
   * happens when only one is. Rendering the first alone put "0/30 at every
   * level when the link's true rate is passed to detect()" on the screen as
   * the whole story, under an instruction to set one control, and an operator
   * who followed it got an honest run reported as detected with an adversary
   * named. A sentence the API ships and the screen drops is worse than one that
   * was never written: it reads as though the question was answered.
   *
   * @param {Object} calibration
   * @returns {HTMLElement}
   */
  function noiseCalibration(calibration) {
    const table = h("table", {}, [
      h("caption", {
        text: `${calibration.what}: ${calibration.source}`,
      }),
      h("thead", {}, [
        h("tr", {}, [
          h("th", { text: "link noise" }),
          h("th", { class: "numeric", text: "runs that fired" }),
        ]),
      ]),
    ]);
    const body = h("tbody", {});
    (calibration.levels || []).forEach(function (level) {
      body.appendChild(
        h("tr", {}, [
          h("td", { class: "numeric", text: Fmt.rate(level.noise) }),
          h("td", { class: "numeric" }, [
            measured(
              `${Fmt.count(level.detected)} / ${Fmt.count(
                calibration.runs_per_level
              )}`,
              "runs"
            ),
          ]),
        ])
      );
    });
    table.appendChild(body);
    return panel(
      "What the noiseless null costs, measured",
      "not a Phase 5 result, a Phase 4 calibration",
      [
        h("p", {
          class: "note",
          text:
            "Every figure below is MEASURED and carries its sample size. " +
            "None of it is a bound, and none of it is a detection rate for " +
            "any adversary: these are honest runs.",
        }),
        h("div", { class: "table-wrap" }, [table]),
        h("p", {
          class: "note",
          text: calibration.with_true_rate_passed || "",
        }),
        calibration.second_null_note
          ? h("p", { class: "warn-note", text: calibration.second_null_note })
          : notSupplied(["noise_null_calibration.second_null_note"]),
      ]
    );
  }

  /* ---------------------------------------------------------------------- *
   * Ground truth
   * ---------------------------------------------------------------------- */

  /**
   * What the harness knows, in a box that looks like it is outside the system,
   * because it is. The detector may not read any of it.
   *
   * @param {Object} payload
   * @returns {HTMLElement}
   */
  function groundTruth(payload) {
    const truth = payload.ground_truth || {};
    const rows = [
      ["attack", truth.label || truth.attack || Fmt.ABSENT],
      [
        "adversary",
        Fmt.flag(truth.adversary_present, "mounted", "none mounted"),
      ],
      // Only asked when there IS an adversary. On an honest run the harness
      // still reports `acted` for a noisy link, and "adversary: none mounted"
      // sitting above "did it act? yes" reads as a contradiction rather than
      // as the two different facts it is. The link block below says what the
      // wire did.
      truth.adversary_present
        ? [
            "did it act?",
            Fmt.flag(
              truth.acted,
              "yes",
              "no: it was mounted and did nothing on this run"
            ),
          ]
        : null,
      [
        "seams held",
        Fmt.list(truth.seams_held, "none"),
      ],
      [
        "links touched",
        (truth.targeted_links || []).length === 0
          ? "none"
          : (truth.targeted_links || [])
              .map(function (pair) {
                return Fmt.link(pair[0], pair[1]);
              })
              .join(", "),
      ],
      ["detectability", truth.detectable || Fmt.ABSENT],
    ];
    const link = truth.link;
    if (link) {
      rows.push(["link model", `${link.model}: ${link.description}`]);
      rows.push([
        "true error rate",
        Object.keys(link.true_error_rate_by_party || {})
          .map(function (party) {
            return `${party}: ${Fmt.rate(link.true_error_rate_by_party[party])}`;
          })
          .join("   "),
      ]);
      rows.push([
        "nulls the detector was given",
        `rate family ${Fmt.rate(link.rate_null_given_to_detector)} · ` +
          `channel family ${Fmt.rate(link.channel_null_given_to_detector)}`,
      ]);
      rows.push([
        "do the nulls match the link?",
        // Deliberately neutral. WHY they disagree -- a wrong null, or an
        // adversary on the wire -- is a different question with two different
        // answers, and it is settled in the paragraph below rather than
        // asserted in a table cell that cannot know which run it is on.
        Fmt.flag(
          link.nulls_match_link,
          "yes",
          "NO: the wire departs from the law the detector was given"
        ),
      ]);
    }
    const box = h("div", { class: "truth" }, [
      h("h3", { text: "Harness ground truth: not visible to the detector" }),
      kv(rows),
    ]);
    if (link && link.nulls_match_link === false) {
      // WHY the link departs from the null decides which sentence is true,
      // and only the harness knows. With no adversary mounted the departure
      // IS the null being wrong about the wire. With one mounted, the wire
      // departs because the adversary is on it -- and saying "not an attack"
      // there would be a lie in the other direction.
      box.appendChild(h("p", { class: "warn", text: link.note || "" }));
      box.appendChild(
        h("p", {
          class: "warn",
          text: truth.adversary_present
            ? `THE NULLS DO NOT MATCH THIS LINK, and an adversary is mounted ` +
              `on it: the wire departs from the null BECAUSE of the ` +
              `adversary. A transcript cannot separate those two readings, ` +
              `which is exactly why a mismatch or channel signal supports a ` +
              `hypothesis and never excludes one.`
            : `THE NULLS DO NOT MATCH THIS LINK AND NO ADVERSARY IS ` +
              `MOUNTED. Whatever fired below is a departure from a law the ` +
              `run was scored against -- the null being wrong about the ` +
              `wire, and not an attack.`,
        })
      );
    }
    if (truth.notes) {
      box.appendChild(h("p", { class: "warn", text: truth.notes }));
    }
    if (truth.assumption) {
      box.appendChild(h("p", { class: "warn", text: truth.assumption }));
    }
    if (truth.identical_to_honest === true) {
      box.appendChild(
        h("p", {
          class: "warn",
          text:
            "This transcript is IDENTICAL TO AN HONEST ONE, correctly. The " +
            "adversary was mounted and did not act, so there is nothing on " +
            "the wire to detect. A quiet detector here is the right answer, " +
            "not a miss.",
        })
      );
    }
    if (truth.detectable === "undetectable-by-construction") {
      box.appendChild(
        h("p", {
          class: "warn",
          text:
            "UNDETECTABLE BY CONSTRUCTION. Nothing fired because nothing can: " +
            "every statistic on this transcript is drawn from the honest law. " +
            "That is a proof about the model, not a failure of the detector.",
        })
      );
    }
    box.appendChild(
      h("p", {
        class: "warn",
        text:
          "None of the above reached detect(). It reads a JSON transcript and " +
          "nothing else, no session object, no adversary log, no harness " +
          "state.",
      })
    );
    return box;
  }

  /* ---------------------------------------------------------------------- *
   * 5. The channel family
   * ---------------------------------------------------------------------- */

  /**
   * Return the set of link keys that a channel signal fired on.
   *
   * Read off `Signal.name`, whose shape is fixed and documented as
   * `channel:<party>/<bit>:<statistic>` -- the field a results table is meant
   * to group on. No number is derived: this only asks WHICH rows the detector
   * flagged, and the detector did the flagging.
   *
   * @param {Array<Object>} signals
   * @returns {Object} A set-like map from `"Party/bit"` to `true`.
   */
  function firedLinks(signals) {
    const fired = {};
    (signals || []).forEach(function (signal) {
      if (signal.family !== "channel") {
        return;
      }
      const parts = String(signal.name).split(":");
      if (parts.length > 1) {
        fired[parts[1]] = true;
      }
    });
    return fired;
  }

  /**
   * The channel panel: QBER and CHSH per link, or the words "not evaluated".
   *
   * With `check_fraction = 0` the whole family is unevaluable and
   * `detection.withheld` says so. It is drawn as a hatched, dotted NOT
   * EVALUATED state and NOT as a flat healthy line at zero, because an
   * unmonitored link is not a clean one.
   *
   * @param {Object} payload
   * @param {Object} context `{defaults, attacks, constants}`.
   * @returns {HTMLElement}
   */
  function channelPanel(payload, context) {
    const run = payload.run || {};
    const detection = payload.detection || {};
    const links = run.links || [];
    const withheld = detection.withheld || [];

    if (run.channel_evaluable === false || links.length === 0) {
      const reasons = withheld.filter(function (item) {
        return String(item).indexOf("channel") === 0;
      });
      return panel("Channel: QBER and CHSH per link", "not evaluated", [
        h("div", { class: "verdict is-withheld" }, [
          h("div", { class: "headline" }, [
            h("span", {
              class: "glyph",
              text: STATE.withheld.glyph,
              attrs: { "aria-hidden": "true" },
            }),
            h("span", { text: "NOT EVALUATED" }),
          ]),
          h("div", {
            class: "sub",
            text:
              "This run published no check rounds, so there is no independent " +
              "estimate of either link. NO CHART IS DRAWN: a chart of zeros " +
              "would read as a flat healthy line, and an unmonitored link is " +
              "not a clean one.",
          }),
        ]),
        reasons.length > 0
          ? h("p", { class: "note", text: reasons.join("  ·  ") })
          : null,
        h("p", {
          class: "note",
          text:
            "The channel family's roster is four links whether or not a run " +
            "publishes four, so its share of the budget is simply unspendable " +
            "here. That shows up as extra slack in the composite bound, and " +
            "is reported rather than reclaimed.",
        }),
      ]);
    }

    const fired = firedLinks(detection.signals);
    const qberRows = [];
    const chshRows = [];
    // The API's reason for an unevaluable CHSH is a whole sentence, and a whole
    // sentence drawn as SVG text inside a chart cell is centred on that cell
    // and clipped by nothing: at 1024x768 in projector mode it ran 66 px past
    // the right edge of the window. The chart carries a short marker and the
    // sentence is rendered under it as text that wraps.
    const chshReasons = [];
    links.forEach(function (link) {
      const key = `${link.party}/${link.message_bit}`;
      const alarm = fired[key] === true;
      const label = Fmt.link(link.party, link.message_bit);
      const cls = alarm ? "bar-alarm" : "bar-quiet";

      if (link.qber) {
        qberRows.push({
          label: label,
          value: link.qber.value,
          valueLabel: `${Fmt.rate(link.qber.value)}  (${Fmt.count(
            link.qber.errors
          )}/${Fmt.count(link.qber.rounds)})`,
          className: cls,
          interval: link.qber.interval,
          bound: link.qber.bound,
        });
      } else {
        qberRows.push({
          label: label,
          value: null,
          valueLabel: Fmt.ABSENT,
          className: cls,
          unavailable: "no QBER rounds on this link",
        });
      }

      if (link.chsh) {
        chshRows.push({
          label: label,
          value: link.chsh.value,
          valueLabel: `S = ${Fmt.chsh(link.chsh.value)}  (${Fmt.count(
            link.chsh.rounds
          )} rounds)`,
          className: cls,
          interval: link.chsh.interval,
        });
      } else {
        chshRows.push({
          label: label,
          value: null,
          valueLabel: Fmt.ABSENT,
          className: cls,
          unavailable: "NOT EVALUATED: see below",
        });
        chshReasons.push(
          `${label}: ${link.chsh_unavailable || "no CHSH statistic here"}`
        );
      }
    });

    const qberChart = Charts.bars({
      title: "Check-round QBER per link, with its two intervals",
      rows: qberRows,
      domain: { min: 0, max: 1 },
      ticks: [
        { value: 0, label: "0" },
        { value: 0.25, label: "0.25" },
        { value: 0.5, label: "0.5" },
        { value: 0.75, label: "0.75" },
        { value: 1, label: "1" },
      ],
      markers: [],
    });

    // The reference lines come from the API when it supplies them, and
    // otherwise from data/constants.json -- a file this repo ships and a
    // Python test pins against math.sqrt. Two sources, never a third: nothing
    // here computes 2*sqrt(2), and if neither supplies a line, none is drawn.
    const chsh = (context.constants && context.constants.chsh) || {};
    const apiBounds = (context.defaults && context.defaults.bounds) || {};
    const classical = pick(
      [apiBounds, { chsh_classical_bound: chsh.classical_bound }],
      "chsh_classical_bound"
    );
    const tsirelson = pick(
      [apiBounds, { chsh_tsirelson_bound: chsh.tsirelson_bound }],
      "chsh_tsirelson_bound"
    );
    const chshMarkers = [];
    if (Fmt.present(classical)) {
      chshMarkers.push({
        value: classical,
        label: "classical 2",
        className: "marker-reference",
        labelClassName: "reference-label",
      });
    }
    if (Fmt.present(tsirelson)) {
      chshMarkers.push({
        value: tsirelson,
        label: "Tsirelson",
        className: "marker-reference",
        labelClassName: "reference-label",
      });
    }
    const domain = chsh.domain || { minimum: -4, maximum: 4 };
    const chshChart = Charts.bars({
      title: "Check-round CHSH statistic per link",
      rows: chshRows,
      domain: { min: domain.minimum, max: domain.maximum },
      baseline: 0,
      ticks: [
        { value: domain.minimum, label: Fmt.fixed(domain.minimum, 0) },
        { value: 0, label: "0" },
        { value: domain.maximum, label: Fmt.fixed(domain.maximum, 0) },
      ],
      markers: chshMarkers,
    });

    return panel(
      "Channel: QBER and CHSH per link",
      "per link and per message bit, never pooled",
      [
        h("p", {
          class: "note",
          text:
            "Symmetrisation smears the records but never the check logs, so a " +
            "per-link reading is the only one that both detects a " +
            "party-targeted attack and attributes it. Pooling two links would " +
            "report the average of two channels and detect neither, which is " +
            "the exact shape of a one-sided attack.",
        }),
        qberChart,
        h("div", { class: "chart-legend" }, [
          h("span", {}, [
            h("span", { class: "swatch swatch-alarm" }),
            h("span", { text: "a channel threshold fired on this link" }),
          ]),
          h("span", {}, [
            h("span", { class: "swatch swatch-quiet" }),
            h("span", { text: "no channel threshold fired" }),
          ]),
          h("span", { text: "solid whisker: Wilson interval (calibrated)" }),
          h("span", {
            text: "dashed whisker: Hoeffding bound (distribution-free)",
          }),
        ]),
        h("p", {
          class: "note",
          text:
            "The bar colour comes from the detector's own list of fired " +
            "signals, never from comparing a bar to a line here. The channel " +
            "family's operating points are counts of failing check rounds " +
            "rather than rates, so they do not live on this axis; they are in " +
            "the Signals table with their critical values.",
        }),
        chshChart,
        chshReasons.length === 0
          ? null
          : h("div", { class: "panel-body" }, [
              h("p", {
                class: "note",
                text:
                  "Why a link has no CHSH statistic, the API's own sentence, " +
                  "in full. NOT EVALUATED is not a zero and is not a pass:",
              }),
              h(
                "ul",
                {},
                chshReasons.map(function (reason) {
                  return h("li", { class: "note", text: reason });
                })
              ),
            ]),
        h("p", {
          class: "note",
          text:
            chsh.note ||
            "Reference lines are definitions of the CHSH inequality, not " +
              "thresholds this detector applies.",
        }),
        h("p", {
          class: "note",
          text:
            "On a dozen rounds a single link's S can sit below 2 on a " +
            "perfectly honest run, read the interval, and read Signals for " +
            "whether anything actually fired.",
        }),
      ]
    );
  }

  /* ---------------------------------------------------------------------- *
   * The floors
   * ---------------------------------------------------------------------- */

  /**
   * Matched counts against the two floors the run enforces.
   *
   * @param {Object} payload
   * @returns {HTMLElement}
   */
  function floorsPanel(payload) {
    const run = payload.run || {};
    const floors = run.floors;
    const verifiers = run.verifiers || [];
    const pooled = run.pooled || {};
    if (!floors) {
      return panel("Matched counts and the floors", null, [
        notSupplied(["run.floors"]),
      ]);
    }

    const matchedRows = verifiers.map(function (verifier) {
      if (verifier.scored === false) {
        return {
          label: verifier.party,
          value: null,
          valueLabel: "no verdict",
          unavailable: "denied the evidence, nothing to plot",
        };
      }
      return {
        label: verifier.party,
        value: verifier.matched,
        valueLabel: `${Fmt.count(verifier.matched)} of ${Fmt.count(
          verifier.matched_trials
        )}`,
        className: "bar",
      };
    });

    const sifted = run.sifted_key_length;
    const children = [
      h("p", {
        class: "note",
        text:
          "Both floors are enforced by the protocol, not by this screen. " +
          "Whether one bit is a matter of record on the transcript: the " +
          "Signals and Verifiers panels, and never of a bar being shorter " +
          "than a line here.",
      }),
    ];

    if (Fmt.present(sifted)) {
      children.push(
        Charts.bars({
          title: "Matched count per verifier against the per-party floor",
          rows: matchedRows,
          domain: { min: 0, max: sifted },
          ticks: [
            { value: 0, label: "0" },
            { value: sifted, label: Fmt.count(sifted) },
          ],
          markers: Fmt.present(floors.matched_minimum)
            ? [
                {
                  value: floors.matched_minimum,
                  label: `m_min = ${Fmt.count(floors.matched_minimum)}`,
                  className: "marker-floor",
                },
              ]
            : [],
        })
      );
    }

    if (Fmt.present(pooled.trials) && Fmt.present(pooled.count)) {
      children.push(
        Charts.bars({
          title: "Pooled matched count against the pooled floor",
          rows: [
            {
              label: "pooled M",
              value: pooled.count,
              valueLabel: `${Fmt.count(pooled.count)} of ${Fmt.count(
                pooled.trials
              )}`,
              className: "bar",
            },
            {
              label: "declared M",
              value: pooled.declared_pooled,
              valueLabel: Fmt.count(pooled.declared_pooled),
              className: "bar-quiet",
            },
          ],
          domain: { min: 0, max: pooled.trials },
          ticks: [
            { value: 0, label: "0" },
            { value: pooled.trials, label: Fmt.count(pooled.trials) },
          ],
          markers: Fmt.present(floors.pooled_minimum)
            ? [
                {
                  value: floors.pooled_minimum,
                  label: `M_min = ${Fmt.count(floors.pooled_minimum)}`,
                  className: "marker-floor",
                },
              ]
            : [],
        })
      );
    } else {
      children.push(
        h("div", { class: "verdict is-withheld" }, [
          h("div", { class: "headline" }, [
            h("span", {
              class: "glyph",
              text: STATE.withheld.glyph,
              attrs: { "aria-hidden": "true" },
            }),
            h("span", { text: "NO POOLED COUNT" }),
          ]),
          h("div", {
            class: "sub",
            text:
              "This run reached no pair of verdicts to pool, so there is no " +
              "pooled matched count. That is an absent number, not a zero.",
          }),
        ])
      );
    }

    children.push(
      kv([
        [
          "per-party floor m_min",
          plain(Fmt.count(floors.matched_minimum), "positions"),
        ],
        [
          "pooled floor M_min",
          plain(Fmt.count(floors.pooled_minimum), "positions"),
        ],
        [
          "floor bound",
          proven(
            Fmt.exp(floors.matched_floor_bound),
            "P(honest run below the floor)"
          ),
        ],
        [
          "every floor met?",
          Fmt.flag(floors.meets_every_floor, "yes", "NO: see Signals"),
        ],
        [
          "floors degenerate?",
          Fmt.flag(
            floors.degenerate,
            "YES: at this key length the floors carry no claim",
            "no"
          ),
        ],
      ])
    );

    return panel("Matched counts and the floors", "watch the floors", children);
  }

  /* ---------------------------------------------------------------------- *
   * Signals
   * ---------------------------------------------------------------------- */

  /**
   * Every threshold that fired, with what it proves.
   *
   * @param {Object} payload
   * @returns {HTMLElement}
   */
  function signalsPanel(payload) {
    const signals = payload.detection.signals || [];
    if (signals.length === 0) {
      return panel("Signals", "nothing fired", [
        h("p", {
          class: "note",
          text:
            "No derived threshold was crossed at this budget. That is not a " +
            "statement that no attack occurred: there is no false-negative " +
            "bound, and none can be derived from a transcript.",
        }),
      ]);
    }
    const table = h("table", {}, [
      h("thead", {}, [
        h("tr", {}, [
          h("th", { text: "signal" }),
          h("th", { text: "family" }),
          h("th", { text: "kind" }),
          h("th", { text: "statistic" }),
          h("th", { class: "numeric", text: "observed" }),
          h("th", { class: "numeric", text: "critical" }),
          h("th", { text: "proves" }),
        ]),
      ]),
    ]);
    const body = h("tbody", {});
    signals.forEach(function (signal) {
      const row = h("tr", {
        class: signal.is_detection ? "row-detected" : "row-withheld",
      });
      const nameCell = h("td", {}, [h("code", { text: signal.name })]);
      if (!signal.is_detection) {
        nameCell.appendChild(
          h("div", {
            class: "claim",
            text:
              "NOT A DETECTION (C-7): a statement about the transcript file, " +
              "not about an adversary.",
          })
        );
      }
      const claim = h("details", { class: "claim-details" }, [
        h("summary", { text: "what it proves" }),
        h("p", { text: signal.claim }),
      ]);
      row.appendChild(nameCell);
      row.appendChild(h("td", { text: signal.family }));
      row.appendChild(h("td", { text: signal.kind }));
      row.appendChild(h("td", { text: signal.statistic }));
      row.appendChild(
        h("td", {
          class: "numeric",
          text: signal.observed === null ? "n/a" : Fmt.fixed(signal.observed, 4),
        })
      );
      row.appendChild(
        h("td", {
          class: "numeric",
          text: signal.critical === null ? "n/a" : Fmt.fixed(signal.critical, 4),
        })
      );
      row.appendChild(
        h("td", {}, [
          proven(Fmt.exp(signal.false_positive_bound), "under the honest null"),
          claim,
        ])
      );
      body.appendChild(row);
    });
    table.appendChild(body);
    return panel(
      "Signals",
      "each one carries the bound its own threshold proves",
      [
        h("div", { class: "table-wrap" }, [table]),
        h("p", {
          class: "note",
          text:
            "Signals from one threshold share one bound, and the composite " +
            "counts it once: two refusal reasons from a single structural " +
            "check are two rows and one term in the published bound.",
        }),
      ]
    );
  }

  /* ---------------------------------------------------------------------- *
   * 4. Attribution, including (AUTH)
   * ---------------------------------------------------------------------- */

  const SUPPORT_STATE = {
    supported: { kind: "named", label: "SUPPORTED", row: "row-named" },
    unsupported: { kind: "neutral", label: "UNSUPPORTED", row: "" },
    excluded: { kind: "ruledout", label: "RULED OUT", row: "" },
    "undetectable-by-construction": {
      kind: "withheld",
      label: "UNDETECTABLE BY CONSTRUCTION",
      row: "row-undetectable",
    },
  };

  /**
   * One row per hypothesis, always all of them.
   *
   * A hypothesis missing from a table reads as one that was ruled out, and the
   * (AUTH) row in particular is never a blank, a dash or a zero: a zero reads
   * as "we tried and failed", and this is "we proved you cannot, and here is
   * the assumption".
   *
   * @param {Object} payload
   * @param {Array<Object>|null} attacks `GET /api/attacks`, for the assumption
   *   text. Absent is handled.
   * @returns {HTMLElement}
   */
  function attributionPanel(payload, attacks) {
    const rows = payload.detection.attributions || [];
    let authText = null;
    (attacks || []).forEach(function (entry) {
      if (entry.detectable === "undetectable-by-construction") {
        authText = entry.assumption;
      }
    });

    const table = h("table", {}, [
      h("thead", {}, [
        h("tr", {}, [
          h("th", { text: "hypothesis" }),
          h("th", { text: "status" }),
          h("th", { text: "how surely" }),
          h("th", { text: "why" }),
        ]),
      ]),
    ]);
    const body = h("tbody", {});
    rows.forEach(function (row) {
      const spec = SUPPORT_STATE[row.status] || {
        kind: "neutral",
        label: String(row.status),
        row: "",
      };
      const tr = h("tr", { class: spec.row });
      tr.appendChild(h("td", {}, [h("code", { text: row.hypothesis })]));
      tr.appendChild(h("td", {}, [token(spec.kind, spec.label)]));

      const surety = h("td", {});
      if (row.status === "excluded" && Fmt.present(row.false_positive_bound)) {
        surety.appendChild(
          proven(Fmt.exp(row.false_positive_bound), "wrong exclusion at most")
        );
      } else if (
        row.status === "supported" &&
        Fmt.present(row.false_positive_bound)
      ) {
        surety.appendChild(
          proven(Fmt.exp(row.false_positive_bound), "against the honest null")
        );
        surety.appendChild(
          h("div", {
            class: "claim",
            text:
              "NOT P(this adversary rather than another). 'A rather than B' " +
              "has no null, so there is no inequality to invert and nothing " +
              "here derives such a number.",
          })
        );
      } else if (row.status === "undetectable-by-construction") {
        surety.appendChild(token("withheld", "OUT OF MODEL (AUTH)"));
      } else {
        surety.appendChild(
          h("span", { class: "claim", text: "no evidence to bound" })
        );
      }
      tr.appendChild(surety);

      const why = h("td", {}, [
        h("details", { class: "claim-details" }, [
          h("summary", { text: "the mechanism this row was read off" }),
          h("p", { text: row.rationale }),
        ]),
      ]);
      if ((row.indistinguishable_from || []).length > 0) {
        why.appendChild(
          h("div", {
            class: "claim",
            text: `not separable from: ${row.indistinguishable_from.join(", ")}`,
          })
        );
      }
      if ((row.missing_requirements || []).length > 0) {
        why.appendChild(
          h("div", {
            class: "claim",
            text:
              `evaluated and did not fire: ${row.missing_requirements.join(
                ", "
              )}: withheld, never refuted.`,
          })
        );
      }
      tr.appendChild(why);
      body.appendChild(tr);
    });
    table.appendChild(body);

    const children = [
      h("div", { class: "table-wrap" }, [table]),
      banner("info", "⚿", "Full impersonation is out of model", [
        authText ||
          "(AUTH): the classical channel Alice authenticates over is assumed " +
            "authentic. An adversary holding BOTH of Alice's seams runs the " +
            "protocol correctly with a key of her own, so every statistic on " +
            "the transcript is drawn from the honest law.",
        "This row is never a blank and never a zero. A zero would read as " +
          "'we tried and failed'; the claim is 'we proved you cannot, and " +
          "here is the assumption that makes it so'.",
      ]),
    ];
    if (payload.detection.requirements_enforced === false) {
      children.push(
        h("p", {
          class: "note",
          text:
            "Requirements waived on this run: a verifier reached no verdict, " +
            "so a signal a position produces with probability one may simply " +
            "never have been looked for. A hypothesis surviving here is not " +
            "evidence for it.",
        })
      );
    }
    return panel(
      "Attribution",
      "every hypothesis, every run, a missing row reads as one ruled out",
      children
    );
  }

  /* ---------------------------------------------------------------------- *
   * 8. Bounds
   * ---------------------------------------------------------------------- */

  /**
   * The proven numbers, the post-hoc one, and the budget split.
   *
   * @param {Object} payload
   * @returns {HTMLElement}
   */
  function boundsPanel(payload) {
    const detection = payload.detection;
    const budget = detection.budget || {};
    const timings = payload.timings || {};
    return panel(
      "Bounds",
      "publish the proven one; the budget is not the detector's error rate",
      [
        kv([
          [
            "false_positive_bound",
            proven(
              Fmt.exp(detection.false_positive_bound),
              "P(any signal | honest): THE NUMBER TO QUOTE"
            ),
          ],
          [
            "eps (the budget asked for)",
            plain(Fmt.exp(detection.eps), "an input, not a result"),
          ],
          [
            "slack",
            plain(
              Fmt.fixed(detection.slack_factor, 2),
              "how far inside its budget the composite proved"
            ),
          ],
          [
            "evidence_bound",
            detection.evidence_bound === null
              ? h("span", {
                  class: "claim",
                  text: "nothing fired, so there is no post-hoc set to bound",
                })
              : h("span", {}, [
                  proven(Fmt.exp(detection.evidence_bound), "POST HOC"),
                  h("div", {
                    class: "claim",
                    text:
                      "the smallest bound among the signals that DID fire, a " +
                      "set chosen by the data. It is a different statement " +
                      "from the line above and is never the detector's error " +
                      "rate.",
                  }),
                ]),
          ],
        ]),
        h("hr"),
        h("p", { class: "note", text: "How eps was divided (C-2):" }),
        kv([
          ["rate family", plain(Fmt.exp(budget.rate))],
          ["structural family", plain(Fmt.exp(budget.structural))],
          ["channel family", plain(Fmt.exp(budget.channel))],
          ["per link", plain(Fmt.exp(budget.per_link))],
          [
            "link roster",
            plain(
              (budget.link_roster || [])
                .map(function (pair) {
                  return Fmt.link(pair[0], pair[1]);
                })
                .join(", ")
            ),
          ],
        ]),
        h("p", { class: "note", text: budget.derivation || "" }),
        h("hr"),
        h("p", { class: "note" }, [
          h("strong", {
            text: "There is no false-negative bound on this screen ",
          }),
          h("span", {
            text:
              "because there is none to put there. Nothing a transcript " +
              "carries bounds the probability that an adversary went " +
              "unnoticed, so no panel here implies one.",
          }),
        ]),
        h("div", { class: "legend" }, [
          h("span", { text: "cost of this run:" }),
          measured(Fmt.millis(timings.session_ms), "session, 1 run"),
          measured(Fmt.millis(timings.detect_ms), "detect, 1 run"),
        ]),
      ]
    );
  }

  /* ---------------------------------------------------------------------- *
   * 7. Transferability
   * ---------------------------------------------------------------------- */

  /**
   * What this run does and does not establish about non-repudiation.
   *
   * At demo scale both floors are inert and the enforced bound is close to 1,
   * so a green transferability tick here would be a lie. The panel says, in the
   * run's own words and with the run's own numbers, what it cannot establish.
   *
   * @param {Object} payload
   * @param {Object} context `{defaults, attacks, constants}`.
   * @returns {HTMLElement}
   */
  function transferabilityPanel(payload, context) {
    const run = payload.run || {};
    const defaults = context.defaults || {};
    const bounds = defaults.bounds || {};
    const headline = bounds.headline || {};
    const params = defaults.params || {};
    const floors = run.floors || {};
    const headlineBound = pick(
      [headline, bounds],
      "enforced_repudiation_bound"
    );
    const headlineLength = pick([headline, params], "key_length");
    const collapseBelow = pick(
      [bounds, headline],
      "degenerate_below_key_length"
    );
    const claim = run.security_claim;
    const enforced = run.enforced_repudiation_bound;

    const children = [];

    if (claim === false) {
      children.push(
        banner("alarm", "⚠", "This run carries no security claim at all", [
          "Both matched-count floors are degenerate at this sifted length. " +
            "Every number on this page still computes cheerfully, and none of " +
            "them is a security statement.",
          `The floors on this run are m_min = ` +
            `${Fmt.count(floors.matched_minimum)} and M_min = ` +
            `${Fmt.count(floors.pooled_minimum)}; they collapse below a ` +
            `sifted length of about ${Fmt.count(collapseBelow)}.`,
        ])
      );
    }

    children.push(
      kv([
        [
          "transferable (this run)",
          h("span", {}, [
            plain(Fmt.flag(run.transferable, "yes", "no")),
            h("div", {
              class: "claim",
              text:
                "an outcome of THIS run, not a guarantee. It says the two " +
                "verdicts agreed here; it says nothing about how often they " +
                "would.",
            }),
          ]),
        ],
        [
          "repudiated (this run)",
          h("span", {}, [
            plain(Fmt.flag(run.repudiated, "yes", "no")),
            h("div", {
              class: "claim",
              text:
                "cannot distinguish signer misbehaviour from channel noise or " +
                "from recipient forgery. Phase 3 measured plain depolarising " +
                "noise producing this with a completely honest Alice.",
            }),
          ]),
        ],
        [
          "repudiation guarantee (this run's own M)",
          run.repudiation_guarantee === null
            ? h("span", {
                class: "claim",
                text: "none: this run is not a repudiation experiment",
              })
            : proven(Fmt.exp(run.repudiation_guarantee), "per-run bound"),
        ],
        [
          "enforced bound (a priori, from the floors)",
          proven(Fmt.exp(enforced), "P(successful repudiation)"),
        ],
        [
          "at DEFAULT_PARAMS instead",
          Fmt.present(headlineBound)
            ? proven(
                Fmt.exp(headlineBound),
                `key_length ${Fmt.count(headlineLength)}`
              )
            : h("span", { class: "claim", text: "not supplied by the API" }),
        ],
        [
          "are this run's floors live?",
          plain(
            Fmt.flag(
              floors.degenerate,
              "NO: both collapse at this length",
              "yes"
            )
          ),
        ],
        [
          "floors collapse below",
          plain(Fmt.count(collapseBelow), "sifted positions"),
        ],
      ])
    );

    children.push(
      banner(
        "caution",
        "⚠",
        "What a demo-scale run cannot demonstrate",
        [
          "Compare the two bounds above. The enforced bound at this run's " +
            "parameters is a number close to one, which is not a bound on " +
            "anything. The row above it says the length below which the " +
            "floors collapse; that figure comes from the API, like every " +
            "other number here.",
          "So: a green tick beside 'transferable' on this run would be a " +
            "lie. What this run demonstrates is that the machinery runs and " +
            "that the floors and the detector behave as derived. " +
            "NON-REPUDIATION IS NOT DEMONSTRATED HERE, and the parameters at " +
            "which it would be are four minutes of session generation away " +
            "and are shown as parameters rather than as a run.",
        ]
      )
    );

    return panel(
      "Transferability and non-repudiation",
      "what this run does NOT establish",
      children
    );
  }

  /* ---------------------------------------------------------------------- *
   * 6. Grouping, and 5. what was withheld
   * ---------------------------------------------------------------------- */

  /**
   * The run's variant markers.
   *
   * @param {Object} payload
   * @returns {HTMLElement}
   */
  function groupingPanel(payload) {
    const detection = payload.detection || {};
    const run = payload.run || {};
    return panel("Grouping key", "group by this; never average over it", [
      kv([
        [
          "grouping_key",
          plain(Fmt.list(detection.grouping_key, "empty")),
        ],
        ["count_exchange_timing", plain(String(run.count_exchange_timing))],
        ["counts exchanged?", Fmt.flag(run.counts_exchanged, "yes", "no")],
        ["sifted key length", plain(Fmt.count(run.sifted_key_length))],
        ["check fraction", plain(Fmt.fixed(run.check_fraction, 4))],
        ["message bit", plain(Fmt.count(run.message_bit))],
      ]),
      h("p", {
        class: "note",
        text:
          "The two count-exchange orderings answer different questions, one " +
          "is a forgery, the other a denial of service. Timing is a control " +
          "the operator sets and a label on the result. It is never a thing " +
          "summed over, and no total on this page crosses it.",
      }),
    ]);
  }

  /**
   * Checks with no admissible operating point, or statistics this run could
   * not evaluate. A withheld check is not a passed check.
   *
   * @param {Object} payload
   * @returns {HTMLElement|null}
   */
  function withheldPanel(payload) {
    const withheld = payload.detection.withheld || [];
    if (withheld.length === 0) {
      return null;
    }
    const list = h("ul");
    withheld.forEach(function (item) {
      list.appendChild(
        h("li", {}, [token("withheld", "NOT EVALUATED"), h("span", {
          text: ` ${item}`,
        })])
      );
    });
    return panel(
      "Withheld",
      "not evaluated, which is not the same as passed",
      [
        h("p", {
          class: "note",
          text:
            "These checks had no admissible operating point at this budget " +
            "and sample size, or this run could not evaluate them at all. " +
            "They contributed no evidence in either direction.",
        }),
        list,
      ]
    );
  }

  /* ---------------------------------------------------------------------- *
   * A run that did not happen
   * ---------------------------------------------------------------------- */

  /**
   * A run-level failure, rendered as a FOURTH thing that is none of the others.
   *
   * The API answers a failed run with 200 and all four contract keys, with
   * `detection` and `run` null and `error` filled in -- so a failure never
   * arrives as a 500 page and never arrives looking like a quiet detector. The
   * screen has to keep that distinction: a run that did not happen is not a
   * clean run, is not a detection, and is not a no-verdict either. Nothing
   * about it belongs in any rate.
   *
   * @param {Object} payload
   * @returns {HTMLElement|null}
   */
  function failurePanel(payload) {
    const error = payload.error;
    if (!error) {
      return null;
    }
    const rows = Object.keys(error).map(function (key) {
      return [key, String(error[key])];
    });
    return panel("This run did not complete", "not a result of any kind", [
      h("div", { class: "verdict is-withheld" }, [
        h("div", { class: "headline" }, [
          h("span", {
            class: "glyph",
            text: STATE.withheld.glyph,
            attrs: { "aria-hidden": "true" },
          }),
          h("span", { text: "NO RUN" }),
        ]),
        h("div", {
          class: "sub",
          text:
            "The session or the detector did not finish, so there is nothing " +
            "to score. This is NOT a clean run, NOT a detection and NOT a " +
            "no-verdict: those are three things that happened, and this is a " +
            "thing that did not. It belongs in no rate at all.",
        }),
      ]),
      kv(rows),
      h("p", {
        class: "note",
        text:
          "The ground-truth panel below still says which arm was mounted, " +
          "because that is knowable even when the session is not.",
      }),
    ]);
  }

  /**
   * A request the service REFUSED, rendered as the same fourth state.
   *
   * `failurePanel` above covers a run that started and did not finish: the
   * service answers those with 200 and a null body. A request refused by a
   * cap or by the schema never reaches that path -- it is an HTTP 400 or 422,
   * `fetch` rejects, and before this existed the only thing that changed was
   * the status line in the rail. The result area kept the PREVIOUS run on
   * screen, so a refused `key_length = 5000` left a green NOTHING FIRED
   * verdict belonging to a run at 1024 sitting under a control panel reading
   * 5000. That is the failure the cap exists to prevent, arriving by another
   * door: the API refuses rather than clamping precisely so that no result is
   * ever shown under the label of parameters that were not run.
   *
   * TWO CAUSES, TWO PANELS. A request the service answered with a `400` was
   * refused BY the service, and the cap paragraph is the right thing to read
   * next. A `Failed to fetch` was not refused by anybody: the process is not
   * there. Rendering the second under the first's words told a presenter, in
   * front of a room, that a cap had rejected their parameters when the truth
   * was that the demo server had died, and the same copy appeared for a
   * recorded run, which is a static JSON file that no cap has an opinion about.
   * The state is the same fourth state either way; the attribution is not.
   *
   * The sentence is the server's, verbatim. The parameters are the ones the
   * operator typed, echoed back so the panel says what was refused; nothing
   * here is derived (D8).
   *
   * @param {string} message The service's own refusal sentence, or the
   *   transport error.
   * @param {Object} request The control values that were sent.
   * @param {string} [kind] `"refused"` when the service answered and said no,
   *   `"unreachable"` when the fetch itself failed. Defaults to `"refused"`.
   * @returns {HTMLElement}
   */
  function refusalPanel(message, request, kind) {
    const unreachable = kind === "unreachable";
    const rows = Object.keys(request || {}).map(function (key) {
      return [key, String(request[key])];
    });
    return panel(
      unreachable ? "Nothing answered this request" : "This run was refused",
      "not a result of any kind",
      [
        h("div", { class: "verdict is-withheld" }, [
          h("div", { class: "headline" }, [
            h("span", {
              class: "glyph",
              text: STATE.withheld.glyph,
              attrs: { "aria-hidden": "true" },
            }),
            h("span", { text: "NO RUN" }),
          ]),
          h("div", {
            class: "sub",
            text: unreachable
              ? "The request never reached a service. Nothing refused it and " +
                "nothing scored it: the fetch itself failed, which means the " +
                "process serving this page is not answering. This is NOT a " +
                "clean run, NOT a detection and NOT a no-verdict. It belongs " +
                "in no rate at all, and any result previously on this screen " +
                "belonged to a different request and has been cleared."
              : "The service refused this request, so no session was " +
                "generated and nothing was scored. This is NOT a clean run, " +
                "NOT a detection and NOT a no-verdict. It belongs in no rate " +
                "at all, and any result previously on this screen belonged to " +
                "different parameters and has been cleared.",
          }),
        ]),
        h("p", { class: "note", text: message }),
        h("p", {
          class: "note",
          text: unreachable
            ? "No cap was hit and no parameter was rejected, there was " +
              "nobody there to reject one. Check that the server is still " +
              "running; the recorded runs held in this page's memory keep " +
              "working without it."
            : "The request is refused rather than quietly run at the nearest " +
              "allowed value: a screen reporting one run under the label of " +
              "another is the single easiest way for this dashboard to lie.",
        }),
        kv(rows),
      ]
    );
  }

  /**
   * Clear the stage and say that nothing was run, and why.
   *
   * @param {HTMLElement} target
   * @param {string} message
   * @param {Object} request
   * @param {string} [kind] `"refused"` or `"unreachable"`.
   * @returns {void}
   */
  function refused(target, message, request, kind) {
    target.textContent = "";
    target.appendChild(refusalPanel(message, request, kind));
  }

  /* ---------------------------------------------------------------------- *
   * The detector's own words
   * ---------------------------------------------------------------------- */

  /**
   * `Detection.summary()`, verbatim.
   *
   * Worth its own panel: it is the one block on the page whose every figure
   * was formatted in Python, inside the test suite, so the numbers in the
   * chips above can be read against it.
   *
   * @param {Object} payload
   * @returns {HTMLElement}
   */
  function summaryPanel(payload) {
    return panel(
      "The detector's own summary",
      "rendered in Python, verbatim",
      [
        h("pre", {
          class: "summary-pre",
          text: payload.detection.summary || Fmt.ABSENT,
        }),
      ]
    );
  }

  /* ---------------------------------------------------------------------- *
   * Headline parameters
   * ---------------------------------------------------------------------- */

  /**
   * DEFAULT_PARAMS and the bounds they imply, labelled as parameters.
   *
   * No session has been run at this length on this page and the panel says so.
   * A session at L = 115200 is about four minutes and cannot come from a click.
   *
   * @param {Object|null} defaults
   * @returns {HTMLElement}
   */
  function headlineParams(defaults) {
    if (!defaults) {
      return panel("The headline parameter set", null, [
        notSupplied(["/api/defaults"]),
      ]);
    }
    const bounds = defaults.bounds || {};
    const headline = bounds.headline || {};
    const demo = bounds.demo || {};
    const params = defaults.params || {};
    const limits = defaults.limits || {};
    const sources = [headline, bounds, params];

    const costRows = h("tbody", {});
    (limits.cost_table || []).forEach(function (row) {
      costRows.appendChild(
        h("tr", {}, [
          h("td", { class: "numeric", text: Fmt.count(row.key_length) }),
          h("td", { class: "numeric" }, [
            measured(Fmt.count(row.session_ms), "ms, 1 run"),
          ]),
          h("td", { class: "numeric" }, [
            measured(Fmt.count(row.detect_ms), "ms, 1 run"),
          ]),
          h("td", { class: "numeric", text: Fmt.count(row.transcript_kb) }),
        ])
      );
    });

    return panel(
      "The headline parameter set",
      "closed forms \u2014 NO session was run at this length",
      [
        h("p", {
          class: "note",
          text:
            "The decision rule being demonstrated is the SAME rule at both " +
            "sizes; only L differs, and with it whether the floors mean " +
            "anything at all. Every figure below is derived without running " +
            "a session, which is why it can be shown when a run at this " +
            "length cannot.",
        }),
        h("p", { class: "note", text: bounds.note || "" }),
        h("p", { class: "note", text: headline.note || "" }),
        kv([
          ["key_length", plain(Fmt.count(pick(sources, "key_length")))],
          ["s_a", plain(Fmt.rate(params.s_a))],
          ["s_v", plain(Fmt.rate(params.s_v))],
          [
            "m_min",
            plain(
              Fmt.count(pick([headline, {
                minimum_matched: bounds.matched_minimum,
              }], "minimum_matched"))
            ),
          ],
          [
            "M_min",
            plain(
              Fmt.count(pick([headline, {
                minimum_pooled: bounds.pooled_minimum,
              }], "minimum_pooled"))
            ),
          ],
          [
            "floors live at this length?",
            headline.floors_are_live === undefined
              ? plain(Fmt.ABSENT)
              : token(
                  headline.floors_are_live ? "clean" : "withheld",
                  Fmt.flag(headline.floors_are_live, "LIVE", "INERT")
                ),
          ],
          [
            "runnable from this screen?",
            headline.runnable === undefined
              ? plain(Fmt.ABSENT)
              : token(
                  headline.runnable ? "clean" : "withheld",
                  Fmt.flag(
                    headline.runnable,
                    "YES",
                    "NO: about four minutes per session"
                  )
                ),
          ],
          [
            "enforced repudiation bound",
            proven(
              Fmt.exp(pick(sources, "enforced_repudiation_bound")),
              "P(successful repudiation)"
            ),
          ],
          [
            "floors collapse below",
            plain(
              Fmt.count(pick(sources, "degenerate_below_key_length")),
              "sifted positions"
            ),
          ],
        ]),
        h("p", {
          class: "note",
          text:
            "The last two rows are why a demo-scale run cannot demonstrate " +
            "non-repudiation, and why the transferability panel says so in " +
            "the run's own words rather than leaving a reader to compare two " +
            "numbers on different screens.",
        }),
        demo.key_length === undefined
          ? null
          : h("div", { class: "table-wrap" }, [
              h("table", {}, [
                h("caption", {
                  text:
                    "the same decision rule at both sizes; only L differs, " +
                    "and with it whether the floors mean anything. BOTH " +
                    "COLUMNS ARE PARAMETER SETS AND NEITHER IS THIS RUN: " +
                    "the left one is the dashboard's default set at its full " +
                    "key length. A run that spends positions on check rounds " +
                    "is scored at its own shorter sifted length, so its " +
                    "floors and its enforced bound are its own and are on " +
                    "the transferability panel above.",
                }),
                h("thead", {}, [
                  h("tr", {}, [
                    h("th", { text: "" }),
                    h("th", { class: "numeric", text: "demo default set" }),
                    h("th", { class: "numeric", text: "headline set" }),
                  ]),
                ]),
                h("tbody", {}, [
                  compareRow(
                    "key_length",
                    plain(Fmt.count(demo.key_length)),
                    plain(Fmt.count(headline.key_length))
                  ),
                  compareRow(
                    "m_min",
                    plain(Fmt.count(demo.minimum_matched)),
                    plain(Fmt.count(headline.minimum_matched))
                  ),
                  compareRow(
                    "M_min",
                    plain(Fmt.count(demo.minimum_pooled)),
                    plain(Fmt.count(headline.minimum_pooled))
                  ),
                  compareRow(
                    "enforced repudiation bound",
                    proven(Fmt.exp(demo.enforced_repudiation_bound), ""),
                    proven(Fmt.exp(headline.enforced_repudiation_bound), "")
                  ),
                ]),
              ]),
            ]),
        h("p", { class: "note", text: limits.cost_table_note || "" }),
        h("div", { class: "table-wrap" }, [
          h("table", {}, [
            h("caption", {
              text:
                "what a live run costs \u2014 measured, one run each, and the " +
                "reason the live range is capped on key length",
            }),
            h("thead", {}, [
              h("tr", {}, [
                h("th", { class: "numeric", text: "key length" }),
                h("th", { class: "numeric", text: "session" }),
                h("th", { class: "numeric", text: "detect" }),
                h("th", { class: "numeric", text: "transcript KB" }),
              ]),
            ]),
            costRows,
          ]),
        ]),
      ]
    );
  }

  /* ---------------------------------------------------------------------- *
   * The presentation layer: vocabulary
   *
   * Everything below this line is the screen a room looks at. Everything above
   * it is the full report, kept whole, for the person who asks to check a
   * number. The two share one rule and one source: every string is either the
   * API's or `Fmt` applied to a value the API sent.
   * ---------------------------------------------------------------------- */

  /** A verifier's outcome in the words a room reads. Still four-valued. */
  const OUTCOME_WORD = {
    accepted: "Accepted",
    rejected: "Rejected",
    "refused-to-score": "No verdict",
    "not-asked": "Not asked",
  };

  /**
   * A status lamp: glyph, hue and word at once, so no state is carried by
   * colour alone.
   *
   * @param {string} kind A key of `STATE`.
   * @param {string} word
   * @returns {HTMLElement}
   */
  function lamp(kind, word) {
    const spec = STATE[kind] || STATE.neutral;
    return h("span", { class: `lamp ${spec.css}` }, [
      h("span", {
        class: "lamp-glyph",
        text: spec.glyph,
        attrs: { "aria-hidden": "true" },
      }),
      h("span", { text: word }),
    ]);
  }

  /**
   * One verifier's outcome as a lamp.
   *
   * @param {string|null|undefined} outcome
   * @returns {HTMLElement}
   */
  function outcomeLamp(outcome) {
    const spec = OUTCOME_STATE[outcome];
    if (!spec) {
      return lamp("neutral", "Outcome not supplied");
    }
    return lamp(spec.kind, OUTCOME_WORD[outcome]);
  }

  /**
   * The heading block at the top of a page.
   *
   * @param {string} title
   * @param {string} lead
   * @returns {HTMLElement}
   */
  function pageHead(title, lead) {
    return h("header", { class: "page-head" }, [
      h("h1", { text: title }),
      h("p", { text: lead }),
    ]);
  }

  /**
   * One section of a page.
   *
   * @param {string} title
   * @param {string|null} lead
   * @param {Array<Node|null>} children
   * @param {string} [cls]
   * @returns {HTMLElement}
   */
  function sheet(title, lead, children, cls) {
    const node = h("section", { class: `sheet ${cls || ""}` }, [
      h("h2", { text: title }),
    ]);
    if (lead) {
      node.appendChild(h("p", { class: "lead", text: lead }));
    }
    children.forEach(function (child) {
      if (child) {
        node.appendChild(child);
      }
    });
    return node;
  }

  /**
   * The argument behind a claim, one click away rather than on the page.
   *
   * @param {string} label
   * @param {Array<Node|null>} children
   * @returns {HTMLElement}
   */
  function why(label, children) {
    const node = h("details", { class: "why" }, [
      h("summary", { text: label }),
    ]);
    children.forEach(function (child) {
      if (child) {
        node.appendChild(child);
      }
    });
    return node;
  }

  /**
   * A PROVEN figure: derived from a stated null by a named inequality.
   *
   * The turnstile is the mark and it is never used for anything else, so a
   * proven number and a measured one cannot be confused on sight.
   *
   * @param {string} value Pre-formatted.
   * @param {string} [caption]
   * @returns {HTMLElement}
   */
  function provenFigure(value, caption) {
    return h("p", { class: "figure is-proven" }, [
      h("span", {
        class: "figure-mark",
        text: "⊢",
        attrs: { title: "Proven from a stated assumption" },
      }),
      h("span", { class: "figure-value", text: value }),
      caption ? h("span", { class: "figure-caption", text: caption }) : null,
    ]);
  }

  /**
   * A block that stands where a measurement would be, saying there is none.
   *
   * @param {string} title
   * @param {string} body
   * @returns {HTMLElement}
   */
  function notEvaluated(title, body) {
    return h("div", { class: "not-evaluated" }, [
      lamp("withheld", title),
      h("p", { text: body }),
    ]);
  }

  /** How the detector's signal kinds read aloud, by `Signal.kind`. */
  const SIGNAL_WORDS = {
    mismatch: "Mismatches seen by",
    "count-low": "Declared count too low at",
  };

  /** Signal kinds whose party is the subject of the sentence. */
  const SIGNAL_VERBS = {
    "evidence-shortfall": "refused: not enough evidence to score",
    "forwarding-tamper": "refused: counts came from two different declarations",
  };

  /** Channel statistics, by the last segment of `Signal.name`. */
  const CHANNEL_WORDS = {
    min_fidelity: "Entanglement fidelity too low on",
    qber_errors: "Too many check-round errors on",
  };

  /**
   * A signal's name in words, read off its documented shape.
   *
   * `channel:<party>/<bit>:<statistic>` and `<family>:<kind>:<party>` are the
   * shapes the detector documents. Anything else falls back to the raw name
   * rather than a guess.
   *
   * @param {Object} signal
   * @returns {string}
   */
  function signalLabel(signal) {
    const parts = String(signal.name).split(":");
    if (signal.family === "channel" && CHANNEL_WORDS[parts[2]]) {
      const link = String(parts[1]).split("/");
      return `${CHANNEL_WORDS[parts[2]]} ${Fmt.link(link[0], link[1])}`;
    }
    if (SIGNAL_VERBS[signal.kind] && parts[2]) {
      return `${parts[2]} ${SIGNAL_VERBS[signal.kind]}`;
    }
    if (SIGNAL_WORDS[signal.kind] && parts[2]) {
      return `${SIGNAL_WORDS[signal.kind]} ${parts[2]}`;
    }
    return String(signal.name);
  }

  /**
   * A signal's value and threshold, in the format its statistic needs.
   *
   * @param {Object} signal
   * @param {number|null} value
   * @returns {string}
   */
  function signalValue(signal, value) {
    if (String(signal.name).split(":")[2] === "min_fidelity") {
      return Fmt.fixed(value, 4);
    }
    return Fmt.count(value);
  }

  /**
   * A withheld check in words. The API's sentences pass through untouched;
   * only the terse `channel:<party>/<bit>:chsh` form is read aloud.
   *
   * @param {*} item One entry of `detection.withheld`.
   * @returns {string}
   */
  function withheldLabel(item) {
    const text = String(item);
    if (text.indexOf(" ") !== -1) {
      return text;
    }
    const parts = text.split(":");
    if (parts[0] === "channel" && parts[2] === "chsh") {
      const link = String(parts[1]).split("/");
      return `Bell test on ${Fmt.link(link[0], link[1])}`;
    }
    return text;
  }

  /**
   * A hypothesis key in the roster's own words.
   *
   * @param {string} key
   * @param {Array<Object>|null} attacks
   * @returns {string}
   */
  function hypothesisLabel(key, attacks) {
    let label = null;
    (attacks || []).forEach(function (entry) {
      if (label === null && (entry.hypothesis === key || entry.key === key)) {
        label = entry.label;
      }
    });
    return label || String(key).split("-").join(" ");
  }

  /**
   * The assumption that excludes a hypothesis detection cannot, or null.
   *
   * @param {string} key
   * @param {Array<Object>|null} attacks
   * @returns {string|null}
   */
  function assumptionFor(key, attacks) {
    let found = null;
    (attacks || []).forEach(function (entry) {
      if (found === null && entry.hypothesis === key && entry.assumption) {
        found = entry.assumption;
      }
    });
    return found;
  }

  /* ---------------------------------------------------------------------- *
   * Warnings
   * ---------------------------------------------------------------------- */

  /**
   * Split what `nullBanners` returns into warnings and evidence.
   *
   * A banner is a warning and belongs beside the verdict; the noise calibration
   * table is a measured table with its sample size on it, which is evidence.
   * Splitting on the class leaves `nullBanners` untouched.
   *
   * @param {Object} payload
   * @param {Object} context
   * @returns {{warnings: Array<Node>, evidence: Array<Node>}}
   */
  function splitBanners(payload, context) {
    const warnings = [];
    const evidence = [];
    const abort = noVerdictBanner(payload);
    if (abort) {
      warnings.push(abort);
    }
    nullBanners(payload, context).forEach(function (node) {
      if (node.classList.contains("banner")) {
        warnings.push(node);
        return;
      }
      evidence.push(node);
    });
    return { warnings: warnings, evidence: evidence };
  }

  /**
   * The warning, in one sentence a judge can read, keyed off the same flags.
   *
   * Every branch reads a boolean Python computed (`run.nulls`, the verifier
   * outcomes), in the same order `nullBanners` does, so this line and the
   * banner beneath it cannot disagree. It is a paraphrase for the room; the
   * banner, one click away, is the statement.
   *
   * @param {Object} payload
   * @returns {string}
   */
  function plainWarning(payload) {
    const detection = payload.detection || {};
    const nulls = (payload.run && payload.run.nulls) || null;
    const detected = detection.detected === true;
    const lines = [];
    if ((detection.not_scored || []).length !== 0) {
      lines.push("A verifier reached no verdict, which is not a rejection.");
    }
    const bothDefault = nulls
      ? nulls.both_are_default === true
      : detection.null_is_noiseless === true;
    const oneStated = nulls
      ? nulls.both_are_default === false && nulls.both_are_stated === false
      : false;
    if (oneStated) {
      lines.push(
        "Only one of the two noise settings was given, so ordinary link noise " +
          "can still raise this alarm."
      );
    } else if (bothDefault && detected) {
      lines.push(
        "Scored against a perfect link. Ordinary noise on a real link raises " +
          "this alarm too, so check what actually happened before calling it " +
          "an attack."
      );
    } else if (bothDefault) {
      lines.push("Scored against a perfect link.");
    } else {
      lines.push("Scored against the noise levels the operator gave.");
    }
    return lines.join(" ");
  }

  /**
   * The warnings as one disclosure: the plain sentence and the banner headings
   * always visible, the argument behind a click.
   *
   * @param {Object} payload
   * @param {Array<HTMLElement>} banners
   * @returns {HTMLElement|null}
   */
  function alertShelf(payload, banners) {
    if (banners.length === 0) {
      return null;
    }
    const alarming = banners.some(function (node) {
      return node.classList.contains("alarm");
    });
    const headings = banners.map(function (node) {
      const heading = node.querySelector("h3");
      return heading ? heading.textContent : "";
    });
    const shelf = h("details", {
      class: `alert-shelf ${alarming ? "is-alarm" : ""}`,
    });
    shelf.appendChild(
      h("summary", {}, [
        h("span", {
          class: "shelf-glyph",
          text: alarming ? "⚠" : "ℹ",
          attrs: { "aria-hidden": "true" },
        }),
        h("span", { class: "shelf-text" }, [
          h("span", { class: "shelf-plain", text: plainWarning(payload) }),
          h("span", { class: "shelf-headings", text: headings.join("; ") }),
        ]),
      ])
    );
    banners.forEach(function (node) {
      shelf.appendChild(node);
    });
    return shelf;
  }

  /* ---------------------------------------------------------------------- *
   * The session: phases
   * ---------------------------------------------------------------------- */

  /**
   * One entry per step `QDSSession.run()` takes, in the protocol's own names.
   *
   * `live` lists the routes a message travels in that phase. A phase in which
   * one party reads evidence it already holds moves nothing, and has no live
   * route: the bench shows that party working instead of inventing an arrow.
   */
  const PHASES = {
    distribute: {
      tag: "Phase A",
      title: "Distribute",
      line:
        "Alice sends quantum keys for both possible messages to Bob and to " +
        "Charlie.",
      live: ["beam-bob", "beam-charlie"],
    },
    symmetrise: {
      tag: "Phase A'",
      title: "Swap",
      line:
        "Bob and Charlie privately swap key positions, so Alice cannot tell " +
        "which of them holds what.",
      live: ["private-down", "private-up"],
    },
    sign: {
      tag: "Phase B",
      title: "Sign",
      line:
        "Alice announces which key she signed with, over an authenticated line " +
        "to Bob.",
      live: ["cable-bob"],
    },
    counts: {
      tag: "Phase C'",
      title: "Compare counts",
      line:
        "Bob and Charlie tell each other how many key positions each of them " +
        "can check.",
      live: ["private-down", "private-up"],
    },
    verifyBob: {
      tag: "Phase C",
      title: "Bob checks",
      line:
        "Bob checks the signature against his own key copy. Nothing moves: he " +
        "reads what he already holds.",
      live: [],
      working: "bob",
    },
    forward: {
      tag: "Phase C",
      title: "Forward",
      line:
        "Bob passes the signature on to Charlie. A forging recipient would act " +
        "here.",
      live: ["forward"],
    },
    verifyCharlie: {
      tag: "Phase C",
      title: "Charlie checks",
      line:
        "Charlie checks what reached him against his own copy, with a slightly " +
        "looser cut than Bob's.",
      live: [],
      working: "charlie",
    },
  };

  /**
   * The order this run performed its phases, which the timing control decides.
   *
   * `QDSSession.run()` moves the Bob-to-Charlie hop to before the count
   * exchange when the timing is `after-forwarding`. The two orderings answer
   * different questions, one a forgery and the other a denial of service, so
   * the order is read off the payload rather than drawn the same for both.
   *
   * @param {string} timing `run.count_exchange_timing`.
   * @returns {Array<string>}
   */
  function phaseOrder(timing) {
    if (String(timing) === "after-forwarding") {
      return [
        "distribute",
        "symmetrise",
        "sign",
        "forward",
        "counts",
        "verifyBob",
        "verifyCharlie",
      ];
    }
    return [
      "distribute",
      "symmetrise",
      "sign",
      "counts",
      "verifyBob",
      "forward",
      "verifyCharlie",
    ];
  }

  /**
   * Walk a sequence without counting.
   *
   * `order[order.indexOf(id) + 1]` is arithmetic, which this file may not do
   * (**D8**). Accumulating the answers once by iteration keeps the rule, and
   * `next`, `prev` and `reached` are plain lookups afterwards.
   *
   * @param {Array<string>} ids
   * @returns {{next: Object, prev: Object, reached: Object, last: string}}
   */
  function sequence(ids) {
    const next = {};
    const prev = {};
    const reached = {};
    let seen = {};
    let previous = null;
    ids.forEach(function (id) {
      if (previous !== null) {
        next[previous] = id;
        prev[id] = previous;
      }
      const marks = {};
      Object.keys(seen).forEach(function (key) {
        marks[key] = true;
      });
      marks[id] = true;
      reached[id] = marks;
      seen = marks;
      previous = id;
    });
    return { next: next, prev: prev, reached: reached, last: previous };
  }

  /** Which drawn route each seam puts an adversary on. */
  const SEAM_ROUTES = {
    signer: "cable-bob",
    forwarder: "forward",
    count_exchange: "private-down",
  };

  /** Each recipient's quantum link, by party name. */
  const BEAM_OF = { Bob: "beam-bob", Charlie: "beam-charlie" };

  /**
   * Where the simulator put its adversary and its noise, from ground truth.
   *
   * Harness knowledge only, looked up from the seam names the harness itself
   * reports. Nothing here is inferred from the detector's output, and the pane
   * this feeds is labelled as the simulator's record.
   *
   * @param {Object} truth `ground_truth`.
   * @returns {{adversaries: Array<Object>, impersonated: boolean,
   *            noisy: Array<string>, present: boolean}}
   */
  function adversaryLayout(truth) {
    const facts = truth || {};
    const out = {
      adversaries: [],
      impersonated: false,
      noisy: [],
      present: facts.adversary_present === true,
    };
    const link = facts.link || {};
    // `identical_to_honest` is the harness's own boolean for an adversary that
    // was mounted and did nothing. Its link still reports the depolarising
    // MODEL, at strength zero, so reading the model alone drew a noisy beam on
    // a run whose transcript is byte-for-byte an honest one.
    if (link.model === "depolarising" && facts.identical_to_honest !== true) {
      out.noisy = BEAM_OF[link.targeted_party]
        ? [BEAM_OF[link.targeted_party]]
        : ["beam-bob", "beam-charlie"];
    }
    if (!out.present) {
      return out;
    }
    const idle = facts.identical_to_honest === true;
    const hidden = facts.detectable === "undetectable-by-construction";
    let className = "";
    if (idle) {
      className = "is-idle";
    } else if (hidden) {
      className = "is-hidden";
    }
    const routes = {};
    (facts.seams_held || []).forEach(function (seam) {
      if (seam === "distributor") {
        out.impersonated = true;
        return;
      }
      if (seam === "resource_factory") {
        const beams = {};
        (facts.targeted_links || []).forEach(function (pair) {
          if (BEAM_OF[pair[0]]) {
            beams[BEAM_OF[pair[0]]] = true;
          }
        });
        const chosen = Object.keys(beams);
        (chosen.length === 0 ? ["beam-bob", "beam-charlie"] : chosen).forEach(
          function (id) {
            routes[id] = true;
          }
        );
        return;
      }
      if (SEAM_ROUTES[seam]) {
        routes[SEAM_ROUTES[seam]] = true;
      }
    });
    // Full impersonation also holds the signing seam, but there the adversary
    // IS Alice, and a second component on her own declaration would draw one
    // adversary as two.
    if (out.impersonated) {
      delete routes["cable-bob"];
    }
    Object.keys(routes).forEach(function (id) {
      out.adversaries.push({
        route: id,
        label: idle ? "Adversary, idle" : "Adversary",
        className: className,
      });
    });
    return out;
  }

  /* ---------------------------------------------------------------------- *
   * The session view
   * ---------------------------------------------------------------------- */

  /** How long one phase holds during a replay, in ms. Presentation only. */
  const PHASE_HOLD_MS = 1500;

  /** The running replay, so a rebuilt view never leaves one behind. */
  let playTimer = null;

  /**
   * Stop any replay in progress.
   *
   * @returns {void}
   */
  function stopPlayback() {
    if (playTimer !== null) {
      window.clearInterval(playTimer);
      playTimer = null;
    }
  }

  /**
   * True when the viewer has asked the system for less motion.
   *
   * @returns {boolean}
   */
  function prefersStill() {
    return Boolean(
      window.matchMedia &&
        window.matchMedia("(prefers-reduced-motion: reduce)").matches
    );
  }

  /**
   * The legend under the bench, listing only what this drawing contains.
   *
   * @param {Object} layout From `adversaryLayout`.
   * @returns {HTMLElement}
   */
  function benchKey(layout) {
    /**
     * @param {string} kind
     * @param {string} words
     * @returns {HTMLElement}
     */
    function item(kind, words) {
      return h("li", {}, [
        h("span", {
          class: `key-swatch is-${kind}`,
          attrs: { "aria-hidden": "true" },
        }),
        h("span", { text: words }),
      ]);
    }
    return h("ul", { class: "bench-key" }, [
      item("beam", "Quantum keys, sent as light"),
      item("cable", "Classical message"),
      item("private", "Private line between Bob and Charlie"),
      layout.noisy.length === 0 ? null : item("noisy", "Noisy link"),
      layout.present ? item("hazard", "Adversary") : null,
    ]);
  }

  /**
   * One sentence of harness knowledge the drawing cannot carry on its own.
   *
   * Keyed off `ground_truth`'s booleans only, and shown on the truth pane,
   * never beside the verdict.
   *
   * @param {Object} truth
   * @param {Object} layout From `adversaryLayout`.
   * @returns {HTMLElement|null}
   */
  function truthNote(truth, layout) {
    const facts = truth || {};
    let text = null;
    if (facts.adversary_present === true && facts.identical_to_honest === true) {
      text =
        "The adversary was mounted and did not act, so the transcript is " +
        "identical to an honest one. Nothing firing here is correct.";
    } else if (facts.detectable === "undetectable-by-construction") {
      text =
        "Undetectable by design. This adversary is excluded only by assuming " +
        "the classical channel is authentic, never by the evidence, so no " +
        "alarm here is a proof rather than a miss.";
    } else if (facts.adversary_present !== true && layout.noisy.length !== 0) {
      text =
        "No adversary. The link itself is noisy, and whatever the detector " +
        "concludes about that is about the wire.";
    }
    return text === null ? null : h("p", { class: "truth-note", text: text });
  }

  /**
   * What the detector concluded, from the transcript alone.
   *
   * @param {Object} payload
   * @param {Object} context
   * @returns {Array<HTMLElement>}
   */
  function readout(payload, context) {
    const detection = payload.detection || {};
    const run_ = payload.run || {};
    const outcomes = detection.outcomes || {};
    const detected = detection.detected === true;
    const nodes = [];

    nodes.push(
      h("div", {
        class: `verdict-lamp ${detected ? "is-detected" : "is-clean"}`,
      }, [
        h("span", {
          class: "verdict-glyph",
          text: detected ? STATE.detected.glyph : STATE.clean.glyph,
          attrs: { "aria-hidden": "true" },
        }),
        h("div", {}, [
          h("p", {
            class: "verdict-word",
            text: detected ? "Alarm raised" : "No alarm",
          }),
          h("p", {
            class: "verdict-sub",
            text: detected
              ? "At least one threshold was crossed."
              : "No threshold was crossed. A quiet detector is not proof " +
                "that nothing happened.",
          }),
        ]),
      ])
    );

    const shelf = alertShelf(payload, splitBanners(payload, context).warnings);
    if (shelf) {
      nodes.push(shelf);
    }

    if (detected) {
      const list = h("ul", { class: "fired" });
      (detection.signals || []).forEach(function (signal) {
        if (signal.is_detection !== true) {
          return;
        }
        const numbers =
          Fmt.present(signal.observed) && Fmt.present(signal.critical)
            ? h("p", {
                class: "fired-numbers",
                text: `${signalValue(signal, signal.observed)} against a ` +
                  `threshold of ${signalValue(signal, signal.critical)}`,
              })
            : null;
        list.appendChild(
          h("li", {}, [
            h("span", {
              class: "fired-glyph",
              text: STATE.detected.glyph,
              attrs: { "aria-hidden": "true" },
            }),
            h("div", {}, [
              h("p", { class: "fired-name", text: signalLabel(signal) }),
              numbers,
            ]),
          ])
        );
      });
      nodes.push(
        h("div", { class: "readout-block" }, [
          h("h3", { text: "What crossed a threshold" }),
          list,
        ])
      );
    }

    const verifiers = h("dl", { class: "verifiers" });
    (run_.verifiers || []).forEach(function (row) {
      verifiers.appendChild(h("dt", { text: row.party }));
      const cell = h("dd", {}, [outcomeLamp(outcomes[row.party])]);
      if (row.scored === false) {
        cell.appendChild(
          h("p", {
            class: "verifier-note",
            text: "Denied the evidence, so there was nothing to score.",
          })
        );
      }
      verifiers.appendChild(cell);
    });
    nodes.push(
      h("div", { class: "readout-block" }, [
        h("h3", { text: "Each verifier's decision" }),
        verifiers,
      ])
    );

    // A quiet detector over checks that never ran is the easiest thing on
    // this screen to misread as a clean run, so what was not evaluated sits
    // beside the verdict rather than two views away.
    if (run_.security_claim === false) {
      nodes.push(
        notEvaluated(
          "No security claim at this key length",
          "The evidence minimums collapse at this length, so nothing here is " +
            "a security statement."
        )
      );
    }
    const withheld = detection.withheld || [];
    if (withheld.length !== 0) {
      nodes.push(
        h("div", { class: "readout-block" }, [
          h("h3", { text: "Checks that could not run" }),
          h(
            "ul",
            { class: "withheld-list" },
            withheld.map(function (item) {
              return h("li", {}, [lamp("withheld", withheldLabel(item))]);
            })
          ),
        ])
      );
    }

    nodes.push(
      h("div", { class: "readout-block" }, [
        h("h3", { text: "Chance of a false alarm" }),
        provenFigure(
          Fmt.sci(detection.false_positive_bound),
          "at most, if the run was honest. Proven, not measured."
        ),
      ])
    );
    return nodes;
  }

  /**
   * The session: what happened on the bench, beside what the detector
   * concluded.
   *
   * TWO PANES, AND THE SPLIT IS THE POINT. The left is the simulator's own
   * record: where the adversary sat, which link was noisy. The right is the
   * detector reading the transcript and nothing else. A judge who sees the two
   * side by side understands the project from the layout, and the separation
   * that `payload.py` enforces between `ground_truth` and `detection` is the
   * separation they see.
   *
   * A REPLAY, NOT A LIVE FEED. The transcript is finished before this view is
   * built. The motion carries the order of the phases and the direction of
   * each hop; nothing that moves encodes a rate, a count or a verdict. The
   * detector's conclusion is withheld until the replay ends, which is the one
   * orchestrated moment on the page, and a viewer who has asked for reduced
   * motion gets the finished state straight away.
   *
   * @param {Object} payload
   * @param {Object} context
   * @param {Object} options `{autoplay, title, description, source}`.
   * @returns {HTMLElement}
   */
  function sessionView(payload, context, options) {
    const opts = options || {};
    const run_ = payload.run || {};
    const detection = payload.detection || {};
    const truth = payload.ground_truth || {};
    const outcomes = detection.outcomes || {};
    const order = phaseOrder(run_.count_exchange_timing);
    const walk = sequence(order);
    const layout = adversaryLayout(truth);
    const animate = opts.autoplay === true && !prefersStill();

    let current = animate ? order[0] : walk.last;
    let revealed = !animate;

    const benchBox = h("div", { class: "bench" });
    const timeline = h("ol", { class: "timeline" });
    const caption = h("div", {
      class: "phase-caption",
      attrs: { "aria-live": "polite" },
    });
    const readoutBox = h("div", { class: "readout" });
    const steps = {};

    /**
     * A verifier's mount label: waiting until its own phase is reached.
     *
     * @param {string} party
     * @param {string} phaseId
     * @returns {{stateLabel: string, className: string}}
     */
    function partyState(party, phaseId) {
      if ((walk.reached[current] || {})[phaseId] !== true) {
        return { stateLabel: "Waiting", className: "" };
      }
      const spec = OUTCOME_STATE[outcomes[party]];
      if (!spec) {
        return { stateLabel: "Outcome not supplied", className: "" };
      }
      return {
        stateLabel: `${STATE[spec.kind].glyph} ${OUTCOME_WORD[outcomes[party]]}`,
        className: STATE[spec.kind].css,
      };
    }

    /**
     * Repaint the bench, the caption and the timeline for `current`.
     *
     * @returns {void}
     */
    function paintBench() {
      const spec = PHASES[current];
      const bob = partyState("Bob", "verifyBob");
      const charlie = partyState("Charlie", "verifyCharlie");
      benchBox.textContent = "";
      benchBox.appendChild(
        Charts.bench({
          title: `${spec.title}. ${spec.line}`,
          parties: [
            {
              id: "alice",
              name: "Alice",
              role: layout.impersonated ? "Signer, impersonated" : "Signer",
              impersonated: layout.impersonated,
            },
            {
              id: "bob",
              name: "Bob",
              role: "Verifier",
              stateLabel: bob.stateLabel,
              className: bob.className,
              scanning: spec.working === "bob",
            },
            {
              id: "charlie",
              name: "Charlie",
              role: "Verifier",
              stateLabel: charlie.stateLabel,
              className: charlie.className,
              scanning: spec.working === "charlie",
            },
          ],
          live: spec.live.map(function (route) {
            return { route: route };
          }),
          adversaries: layout.adversaries,
          noisy: layout.noisy,
        })
      );
      caption.textContent = "";
      caption.appendChild(h("p", { class: "phase-tag", text: spec.tag }));
      caption.appendChild(h("p", { class: "phase-title", text: spec.title }));
      caption.appendChild(h("p", { class: "phase-line", text: spec.line }));
      order.forEach(function (id) {
        const reached = (walk.reached[current] || {})[id] === true;
        steps[id].className = `step ${id === current ? "is-current" : ""} ${
          reached ? "is-reached" : ""
        }`;
        steps[id].setAttribute(
          "aria-current",
          id === current ? "step" : "false"
        );
      });
    }

    const skipButton = h("button", {
      class: "control",
      text: "Show the result now",
      attrs: { type: "button" },
    });

    /**
     * Repaint the detector pane.
     *
     * @returns {void}
     */
    function paintReadout() {
      readoutBox.textContent = "";
      if (!revealed) {
        readoutBox.appendChild(
          h("div", { class: "readout-waiting" }, [
            h("p", { class: "waiting-title", text: "Replaying the session" }),
            h("p", {
              text: "The detector's conclusion appears when the replay ends.",
            }),
            skipButton,
          ])
        );
        return;
      }
      readout(payload, context).forEach(function (node) {
        readoutBox.appendChild(node);
      });
    }

    /**
     * @param {string} id
     * @returns {void}
     */
    function goTo(id) {
      current = id;
      paintBench();
      if (id === walk.last && !revealed) {
        revealed = true;
        paintReadout();
      }
    }

    /**
     * Run the replay from the first phase.
     *
     * @returns {void}
     */
    function play() {
      stopPlayback();
      if (prefersStill()) {
        goTo(walk.last);
        return;
      }
      revealed = false;
      paintReadout();
      goTo(order[0]);
      playTimer = window.setInterval(function () {
        const after = walk.next[current];
        if (after === undefined) {
          stopPlayback();
          return;
        }
        goTo(after);
      }, PHASE_HOLD_MS);
    }

    const replayButton = h("button", {
      class: "control is-primary",
      text: "Replay",
      attrs: { type: "button" },
    });
    replayButton.addEventListener("click", play);

    const backButton = h("button", {
      class: "control",
      text: "Previous step",
      attrs: { type: "button" },
    });
    backButton.addEventListener("click", function () {
      stopPlayback();
      if (walk.prev[current] !== undefined) {
        goTo(walk.prev[current]);
      }
    });

    const nextButton = h("button", {
      class: "control",
      text: "Next step",
      attrs: { type: "button" },
    });
    nextButton.addEventListener("click", function () {
      stopPlayback();
      if (walk.next[current] !== undefined) {
        goTo(walk.next[current]);
      }
    });

    skipButton.addEventListener("click", function () {
      stopPlayback();
      goTo(walk.last);
    });

    order.forEach(function (id) {
      const button = h("button", { class: "step", attrs: { type: "button" } }, [
        h("span", { class: "step-dot", attrs: { "aria-hidden": "true" } }),
        h("span", { class: "step-name", text: PHASES[id].title }),
      ]);
      button.addEventListener("click", function () {
        stopPlayback();
        goTo(id);
      });
      steps[id] = button;
      timeline.appendChild(h("li", {}, [button]));
    });

    const view = h("div", { class: "session" }, [
      h("header", { class: "session-head" }, [
        h("div", { class: "session-titles" }, [
          h("h1", { text: opts.title || String(truth.label || "This run") }),
          opts.description
            ? h("p", { class: "session-why", text: opts.description })
            : null,
        ]),
        opts.source
          ? h("span", { class: "source-tag", text: opts.source })
          : null,
      ]),
      h("div", { class: "session-grid" }, [
        h("section", {
          class: "pane pane-truth",
          attrs: { "aria-label": "What actually happened" },
        }, [
          h("div", { class: "pane-head" }, [
            h("h2", { text: "What actually happened" }),
            h("p", {
              text:
                "The simulator's own record. The detector never sees this side.",
            }),
          ]),
          benchBox,
          benchKey(layout),
          truthNote(truth, layout),
          h("div", { class: "transport" }, [
            timeline,
            h("div", { class: "transport-row" }, [
              h("div", { class: "controls" }, [
                replayButton,
                backButton,
                nextButton,
              ]),
              caption,
            ]),
          ]),
        ]),
        h("section", {
          class: "pane pane-detector",
          attrs: { "aria-label": "What the detector concluded" },
        }, [
          h("div", { class: "pane-head" }, [
            h("h2", { text: "What the detector concluded" }),
            h("p", { text: "From the published transcript alone." }),
          ]),
          readoutBox,
        ]),
      ]),
    ]);

    paintBench();
    paintReadout();
    if (animate) {
      play();
    }
    return view;
  }

  /* ---------------------------------------------------------------------- *
   * The evidence view: measurements only
   * ---------------------------------------------------------------------- */

  /**
   * What was measured on this run.
   *
   * MEASURED AND PROVEN LIVE ON DIFFERENT PAGES. This page holds counts and
   * rates read off the transcript, each with its sample; the proven bounds are
   * on Proof. The two kinds of number never share a column, and here they do
   * not even share a page.
   *
   * @param {Object} payload
   * @param {Object} context
   * @returns {Array<HTMLElement>}
   */
  function evidenceView(payload, context) {
    const run_ = payload.run || {};
    const detection = payload.detection || {};
    const links = run_.links || [];
    const evaluable = !(run_.channel_evaluable === false || links.length === 0);
    const fired = firedLinks(detection.signals);
    const nodes = [
      pageHead(
        "Evidence",
        "What was measured on this run, counted from the transcript. Bounds " +
          "that are proven rather than measured are on the Proof page."
      ),
      // The warning rides on every view about a run. On an honest run over a
      // noisy link this page shows every link fired, and without the shelf
      // that reads as an attack measured on all four.
      alertShelf(payload, splitBanners(payload, context).warnings),
    ];

    if (!evaluable) {
      nodes.push(
        sheet("Link measurements", null, [
          notEvaluated(
            "Not evaluated",
            "This run published no check rounds, so neither link was " +
              "measured. An unmonitored link is not a clean one."
          ),
        ])
      );
    } else {
      const qberRows = [];
      const chshRows = [];
      const reasons = [];
      links.forEach(function (link) {
        const label = Fmt.link(link.party, link.message_bit);
        const cls =
          fired[`${link.party}/${link.message_bit}`] === true
            ? "bar-alarm"
            : "bar-quiet";
        qberRows.push(
          link.qber
            ? {
                label: label,
                value: link.qber.value,
                valueLabel: `${Fmt.rate(link.qber.value)}  (${Fmt.count(
                  link.qber.errors
                )} of ${Fmt.count(link.qber.rounds)})`,
                className: cls,
                interval: link.qber.interval,
              }
            : {
                label: label,
                value: null,
                valueLabel: Fmt.ABSENT,
                unavailable: "no check rounds",
              }
        );
        if (link.chsh) {
          chshRows.push({
            label: label,
            value: link.chsh.value,
            valueLabel: `${Fmt.chsh(link.chsh.value)}  (${Fmt.count(
              link.chsh.rounds
            )} rounds)`,
            className: cls,
            interval: link.chsh.interval,
          });
        } else {
          chshRows.push({
            label: label,
            value: null,
            valueLabel: Fmt.ABSENT,
            unavailable: "not evaluated",
          });
          reasons.push(
            `${label}: ${link.chsh_unavailable || "no Bell test on this link"}`
          );
        }
      });

      const chsh = (context.constants && context.constants.chsh) || {};
      const apiBounds = (context.defaults && context.defaults.bounds) || {};
      const classical = pick(
        [apiBounds, { chsh_classical_bound: chsh.classical_bound }],
        "chsh_classical_bound"
      );
      const tsirelson = pick(
        [apiBounds, { chsh_tsirelson_bound: chsh.tsirelson_bound }],
        "chsh_tsirelson_bound"
      );
      const markers = [];
      if (Fmt.present(classical)) {
        markers.push({
          value: classical,
          label: "classical limit",
          className: "marker-reference",
          labelClassName: "reference-label",
        });
      }
      if (Fmt.present(tsirelson)) {
        markers.push({
          value: tsirelson,
          label: "quantum limit",
          className: "marker-reference",
          labelClassName: "reference-label",
        });
      }
      // The statistic's own algebraic range. Narrower would clamp a negative S
      // onto zero, drawing a link that anti-correlates as one that measured
      // nothing.
      const domain = chsh.domain || { minimum: -4, maximum: 4 };

      nodes.push(
        sheet(
          "Link measurements",
          "Each link's error rate and Bell test, from its published check " +
            "rounds. A red bar is a link the detector fired on.",
          [
            h("h3", {
              class: "chart-title",
              text: "Error rate. Zero is a perfect link.",
            }),
            Charts.bars({
              title: "Check-round error rate per link",
              rows: qberRows,
              domain: { min: 0, max: 1 },
              ticks: [
                { value: 0, label: "0" },
                { value: 0.5, label: "0.5" },
                { value: 1, label: "1" },
              ],
              markers: [],
            }),
            h("h3", {
              class: "chart-title",
              text: "Bell test. Above the classical limit means entanglement.",
            }),
            Charts.bars({
              title: "Check-round CHSH statistic per link",
              rows: chshRows,
              domain: { min: domain.minimum, max: domain.maximum },
              baseline: 0,
              ticks: [
                { value: domain.minimum, label: Fmt.fixed(domain.minimum, 0) },
                { value: 0, label: "0" },
                { value: domain.maximum, label: Fmt.fixed(domain.maximum, 0) },
              ],
              markers: markers,
            }),
            h("p", {
              class: "chart-note",
              text:
                "Whiskers are confidence intervals. The two limits are " +
                "definitions of the Bell test, not thresholds the detector " +
                "applies.",
            }),
            reasons.length === 0
              ? null
              : why(
                  "Why some links have no Bell test",
                  reasons.map(function (reason) {
                    return h("p", { text: reason });
                  })
                ),
          ]
        )
      );
    }

    const floors = run_.floors || {};
    const pooled = run_.pooled || {};
    const volume = [];
    if (floors.degenerate === true) {
      volume.push(
        notEvaluated(
          "No security claim at this key length",
          "The minimums below are degenerate here. Every number still " +
            "computes, and none of them is a security statement."
        )
      );
    }
    if (Fmt.present(run_.sifted_key_length)) {
      volume.push(
        h("h3", { class: "chart-title", text: "Matched positions per verifier" }),
        Charts.bars({
          title: "Matched count per verifier against the per-party minimum",
          rows: (run_.verifiers || []).map(function (row) {
            if (row.scored === false) {
              return {
                label: row.party,
                value: null,
                valueLabel: "no verdict",
                unavailable: "denied the evidence",
              };
            }
            return {
              label: row.party,
              value: row.matched,
              valueLabel: `${Fmt.count(row.matched)} of ${Fmt.count(
                row.matched_trials
              )}`,
              className: "bar",
            };
          }),
          domain: { min: 0, max: run_.sifted_key_length },
          ticks: [
            { value: 0, label: "0" },
            {
              value: run_.sifted_key_length,
              label: Fmt.count(run_.sifted_key_length),
            },
          ],
          markers: Fmt.present(floors.matched_minimum)
            ? [
                {
                  value: floors.matched_minimum,
                  label: `minimum ${Fmt.count(floors.matched_minimum)}`,
                  className: "marker-floor",
                },
              ]
            : [],
        })
      );
    }
    if (Fmt.present(pooled.trials) && Fmt.present(pooled.count)) {
      volume.push(
        h("h3", { class: "chart-title", text: "Matched positions, pooled" }),
        Charts.bars({
          title: "Pooled matched count against the pooled minimum",
          rows: [
            {
              label: "counted",
              value: pooled.count,
              valueLabel: `${Fmt.count(pooled.count)} of ${Fmt.count(
                pooled.trials
              )}`,
              className: "bar",
            },
            {
              label: "declared",
              value: pooled.declared_pooled,
              valueLabel: Fmt.count(pooled.declared_pooled),
              className: "bar-quiet",
            },
          ],
          domain: { min: 0, max: pooled.trials },
          ticks: [
            { value: 0, label: "0" },
            { value: pooled.trials, label: Fmt.count(pooled.trials) },
          ],
          markers: Fmt.present(floors.pooled_minimum)
            ? [
                {
                  value: floors.pooled_minimum,
                  label: `minimum ${Fmt.count(floors.pooled_minimum)}`,
                  className: "marker-floor",
                },
              ]
            : [],
        })
      );
    } else {
      volume.push(
        notEvaluated(
          "No pooled count",
          "This run reached no pair of verdicts to pool. That is an absent " +
            "number, not a zero."
        )
      );
    }
    nodes.push(
      sheet(
        "How much evidence each verifier had",
        "Key positions each verifier could check, against the minimum the " +
          "protocol requires before it will decide.",
        volume
      )
    );

    const signals = detection.signals || [];
    nodes.push(
      sheet(
        "Thresholds",
        "Every threshold the detector checked that was crossed, with the " +
          "value that crossed it.",
        [
          signals.length === 0
            ? h("p", { class: "empty", text: "No threshold was crossed." })
            : h("div", { class: "table-wrap" }, [
                h("table", { class: "grid" }, [
                  h("thead", {}, [
                    h("tr", {}, [
                      h("th", { text: "What" }),
                      h("th", { class: "numeric", text: "Value" }),
                      h("th", { class: "numeric", text: "Threshold" }),
                      h("th", { text: "Counts as an alarm" }),
                    ]),
                  ]),
                  h(
                    "tbody",
                    {},
                    signals.map(function (signal) {
                      return h("tr", {}, [
                        h("td", { text: signalLabel(signal) }),
                        h("td", {
                          class: "numeric",
                          text: signalValue(signal, signal.observed),
                        }),
                        h("td", {
                          class: "numeric",
                          text: signalValue(signal, signal.critical),
                        }),
                        h("td", {}, [
                          signal.is_detection === true
                            ? lamp("detected", "Yes")
                            : lamp("withheld", "No, a fact about the file"),
                        ]),
                      ]);
                    })
                  ),
                ]),
              ]),
        ]
      )
    );

    const withheld = detection.withheld || [];
    if (withheld.length !== 0) {
      nodes.push(
        sheet(
          "Not evaluated",
          "Checks the detector could not run on this transcript. Each is " +
            "absent, not passed.",
          [
            h(
              "ul",
              { class: "withheld-list" },
              withheld.map(function (item) {
                return h("li", {}, [lamp("withheld", withheldLabel(item))]);
              })
            ),
          ]
        )
      );
    }

    const calibration = splitBanners(payload, context).evidence;
    if (calibration.length !== 0) {
      nodes.push(
        sheet(
          "How often honest noise raises an alarm",
          "Measured separately, over many honest runs at each noise level.",
          calibration
        )
      );
    }
    return nodes;
  }

  /* ---------------------------------------------------------------------- *
   * The proof view: proven bounds only
   * ---------------------------------------------------------------------- */

  /** An attribution status in words, and the lamp it lights. */
  const SUSPECT = {
    supported: { kind: "named", word: "Consistent with the evidence" },
    excluded: { kind: "ruledout", word: "Ruled out" },
    unsupported: { kind: "neutral", word: "No evidence either way" },
    "undetectable-by-construction": {
      kind: "withheld",
      word: "Undetectable by design",
    },
  };

  /**
   * What is proven about this run, and what is not.
   *
   * @param {Object} payload
   * @param {Object} context
   * @returns {Array<HTMLElement>}
   */
  function proofView(payload, context) {
    const detection = payload.detection || {};
    const run_ = payload.run || {};
    const defaults = context.defaults || {};
    const bounds = defaults.bounds || {};
    const headline = bounds.headline || {};
    const nodes = [
      pageHead(
        "Proof",
        "What is proven about this run from a stated assumption and a named " +
          "inequality. Nothing on this page is a measurement."
      ),
      // An honest run scored against the wrong null lists "Honest run: ruled
      // out" below. That row is correct about the null it was given and wrong
      // about the wire, and the shelf is what says so.
      alertShelf(payload, splitBanners(payload, context).warnings),
    ];

    nodes.push(
      sheet(
        "Chance of a false alarm",
        null,
        [
          h("p", { class: "hero-figure" }, [
            h("span", { class: "figure-mark", text: "⊢" }),
            h("span", {
              class: "figure-value",
              text: Fmt.sci(detection.false_positive_bound),
            }),
          ]),
          h("p", {
            class: "lead",
            text:
              "If this run was honest, the detector raises an alarm with at " +
              `most this probability. The budget it was given is ` +
              `${Fmt.sci(detection.eps)}.`,
          }),
          detection.bound_is_unconditional === false
            ? h("p", {
                class: "caveat",
                text:
                  "This bound is conditional on the run's matched counts, " +
                  "because a noise rate was given for the rate check.",
              })
            : null,
          why("How the budget is split", [
            h("p", {
              class: "derivation",
              text: String((detection.budget || {}).derivation || Fmt.ABSENT),
            }),
          ]),
        ],
        "is-hero"
      )
    );

    nodes.push(
      sheet("What cannot be promised", null, [
        h("p", {
          class: "statement",
          text:
            "There is no bound on missed attacks, and none can be derived from " +
            "a transcript. A quiet detector is not proof that nothing happened.",
        }),
      ])
    );

    const suspects = h("ul", { class: "suspects" });
    (detection.attributions || []).forEach(function (row) {
      const spec = SUSPECT[row.status] || {
        kind: "neutral",
        word: String(row.status),
      };
      const item = h("li", { class: "suspect" }, [
        h("p", {
          class: "suspect-name",
          text: hypothesisLabel(row.hypothesis, context.attacks),
        }),
        lamp(spec.kind, spec.word),
      ]);
      const twins = row.indistinguishable_from || [];
      if (twins.length !== 0) {
        item.appendChild(
          h("p", {
            class: "suspect-note",
            text: `Cannot be told apart from ${twins
              .map(function (key) {
                return hypothesisLabel(key, context.attacks);
              })
              .join(", ")}.`,
          })
        );
      }
      if (row.status === "undetectable-by-construction") {
        item.appendChild(
          h("p", {
            class: "suspect-note",
            text:
              assumptionFor(row.hypothesis, context.attacks) ||
              "Excluded only by an assumption, never by the evidence.",
          })
        );
      }
      suspects.appendChild(item);
    });
    nodes.push(
      sheet(
        "Possible explanations",
        "The detector's attribution, reasoned from the transcript alone.",
        [suspects]
      )
    );

    const headlineLength = pick([headline, defaults.params || {}], "key_length");
    nodes.push(
      sheet(
        "Can the signer deny it later",
        "The chance a signer gets one verifier to accept and the other to " +
          "reject.",
        [
          run_.security_claim === false
            ? notEvaluated(
                "No security claim at this key length",
                "The evidence minimums collapse at this length, so this run " +
                  "carries no security statement at all."
              )
            : null,
          h("div", { class: "figure-pair" }, [
            h("div", {}, [
              h("h3", { text: "This run" }),
              provenFigure(Fmt.sci(run_.enforced_repudiation_bound)),
            ]),
            h("div", {}, [
              h("h3", {
                text: `Full length, ${Fmt.count(headlineLength)} key positions`,
              }),
              provenFigure(
                Fmt.sci(pick([headline, bounds], "enforced_repudiation_bound"))
              ),
            ]),
          ]),
          h("p", {
            class: "lead",
            text:
              "A demo-length run shows the machinery working. It does not " +
              "demonstrate non-repudiation: that needs the full length, which " +
              "takes minutes per session, so it is shown as a bound rather " +
              "than as a run.",
          }),
        ]
      )
    );
    return nodes;
  }

  /* ---------------------------------------------------------------------- *
   * The full report
   * ---------------------------------------------------------------------- */

  /**
   * Every panel, for the person who asks to check a number.
   *
   * Appended one call at a time rather than assembled as a list, so that each
   * panel's presence on every run is a line a reader can find: the grouping
   * panel in particular is constraint 6, and a list built by `concat` is one
   * dropped element away from losing it silently.
   *
   * @param {HTMLElement} target
   * @param {Object} payload
   * @param {Object} context
   * @returns {void}
   */
  function reportView(target, payload, context) {
    const split = splitBanners(payload, context);
    target.appendChild(
      pageHead(
        "Full report",
        "Every panel and every number, with the reasoning behind each. For " +
          "checking the result rather than presenting it."
      )
    );
    target.appendChild(verdictStrip(payload));
    split.warnings.forEach(function (node) {
      target.appendChild(node);
    });
    target.appendChild(groundTruth(payload));
    target.appendChild(channelPanel(payload, context));
    target.appendChild(floorsPanel(payload));
    target.appendChild(signalsPanel(payload));
    const held = withheldPanel(payload);
    if (held) {
      target.appendChild(held);
    }
    target.appendChild(attributionPanel(payload, context.attacks));
    target.appendChild(boundsPanel(payload));
    target.appendChild(transferabilityPanel(payload, context));
    target.appendChild(groupingPanel(payload));
    split.evidence.forEach(function (node) {
      target.appendChild(node);
    });
    target.appendChild(summaryPanel(payload));
    target.appendChild(headlineParams(context.defaults));
  }

  /* ---------------------------------------------------------------------- *
   * Assembly
   * ---------------------------------------------------------------------- */

  /**
   * Render one page of a `POST /api/run` response into a container.
   *
   * @param {HTMLElement} target
   * @param {string} pageId `session`, `evidence`, `proof` or `report`.
   * @param {Object} payload
   * @param {Object} context `{defaults, attacks, constants}`.
   * @param {Object} [options] Passed to the session view.
   * @returns {void}
   */
  function page(target, pageId, payload, context, options) {
    // Any replay belongs to the view that started it, and that view is about
    // to be thrown away.
    stopPlayback();
    target.textContent = "";
    // A failed run is answered with 200 and null bodies, so it is handled
    // before the contract check -- otherwise the screen would report a
    // contract mismatch for a response that is exactly to contract.
    const failure = failurePanel(payload);
    if (failure) {
      target.appendChild(failure);
      target.appendChild(groundTruth(payload));
      return;
    }
    const check = Contract.checkRun(payload);
    if (!check.ok) {
      target.appendChild(
        panel("The API response does not match the contract", null, [
          notSupplied(check.problems),
        ])
      );
      if (!payload || !payload.detection || !payload.run) {
        return;
      }
    }

    if (pageId === "report") {
      reportView(target, payload, context);
      return;
    }
    let nodes;
    if (pageId === "evidence") {
      nodes = evidenceView(payload, context);
    } else if (pageId === "proof") {
      nodes = proofView(payload, context);
    } else {
      nodes = [sessionView(payload, context, options)];
    }
    nodes.forEach(function (node) {
      if (node) {
        target.appendChild(node);
      }
    });
  }

  /**
   * Render a whole `POST /api/run` response: every panel, as the full report.
   *
   * The entry point this module has always exposed, kept to its original
   * meaning. The page itself goes through `page`, one view at a time; this is
   * the everything-at-once rendering that the value-level tests execute, so a
   * panel moved between views is still a panel they read.
   *
   * @param {HTMLElement} target
   * @param {Object} payload
   * @param {Object} context
   * @returns {void}
   */
  function run(target, payload, context) {
    page(target, "report", payload, context, {});
  }

  return {
    banner: banner,
    h: h,
    headlineParams: headlineParams,
    kv: kv,
    notSupplied: notSupplied,
    page: page,
    panel: panel,
    refused: refused,
    run: run,
    stop: stopPlayback,
    token: token,
  };
})();
