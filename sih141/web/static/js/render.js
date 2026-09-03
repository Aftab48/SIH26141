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
      `No verdict — ${notScored.join(", ")}`,
      [
        "This is a THIRD STATE. It is not an acceptance and it is not a " +
          "rejection: the verifier was asked, was denied the evidence a " +
          "verdict needs, and learned nothing at all about the signature.",
        named.length > 0
          ? `reason on the transcript — ${named.join("; ")}`
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
   * Say which null the mismatch members were scored against, whenever it is
   * the noiseless one -- which is `detect()`'s default.
   *
   * This is the dashboard's worst failure mode: an honest run over a noisy
   * link departs from the noiseless null and is correctly reported as detected,
   * so the baseline lights up red in front of an audience. The banner is what
   * turns that from a lie into a lesson.
   *
   * @param {Object} payload
   * @param {Object} context `{defaults, attacks, constants}`. Any of them may
   *   be missing; the panel that needed one says so rather than inventing it.
   * @returns {Array<Node>}
   */
  function nullBanners(payload, context) {
    const detection = payload.detection;
    const out = [];

    if (detection.null_is_noiseless === true) {
      const paragraphs = [
        "detect() was given channel_error_rate = 0.0, which is its default. " +
          "The null for every mismatch member is therefore that a matched " +
          "position NEVER disagrees.",
        "An honest run over a noisy link departs from that null and is " +
          "reported as detected. The arithmetic is right; the row is still a " +
          "false claim if nobody says which null it was scored against. Set " +
          "the link's true rate in the controls to score it against that " +
          "instead — the value is never inferred from the transcript, " +
          "because at check_fraction = 0 the transcript does not carry it and " +
          "guessing would be inventing a null.",
      ];
      if (detection.detected === true) {
        paragraphs.unshift(
          "THIS RUN FIRED, AND IT WAS SCORED AGAINST THE NOISELESS NULL. " +
            "Read the ground-truth box before reading this as an adversary."
        );
      }
      // The harness knows whether the nulls actually matched the link, and the
      // detector does not. Saying so here turns a standing caution into a
      // statement about THIS run -- and it is the harness's sentence, quoted,
      // not an inference drawn from the transcript.
      const truthLink = (payload.ground_truth || {}).link;
      if (truthLink && truthLink.nulls_match_link === true) {
        paragraphs.push(
          "On this run the harness confirms the nulls DO match the link, so " +
            "the noiseless null is not the explanation for anything that " +
            "fired. That is the harness's knowledge and not the detector's."
        );
      } else if (truthLink && truthLink.nulls_match_link === false) {
        paragraphs.push(
          (payload.ground_truth || {}).adversary_present
            ? "On this run the harness confirms the nulls do not match the " +
                "link AND that an adversary is mounted on it. Both readings " +
                "fit the same transcript; the detector cannot separate them, " +
                "and this screen does not pretend it can."
            : "On this run the harness confirms the nulls do NOT match the " +
                "link, and that no adversary is mounted. What fired is the " +
                "null being wrong about the wire."
        );
      }
      out.push(
        banner(
          detection.detected === true ? "alarm" : "caution",
          "⚠",
          "The null is noiseless",
          paragraphs
        )
      );
    } else {
      out.push(
        banner("info", "ℹ", "The null carries the link's error rate", [
          `The mismatch members were scored against channel_error_rate = ` +
            `${Fmt.rate(detection.channel_error_rate)}, supplied by the ` +
            `operator rather than read off the transcript.`,
          "The channel family is unaffected: its null is the ideal " +
            "entanglement resource, so a noisy link still departs from it and " +
            "a channel signal here is not a mismatch signal.",
        ])
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
   * @param {Object} calibration
   * @returns {HTMLElement}
   */
  function noiseCalibration(calibration) {
    const table = h("table", {}, [
      h("caption", {
        text: `${calibration.what} — ${calibration.source}`,
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
      "not a Phase 5 result — a Phase 4 calibration",
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
              "no — it was mounted and did nothing on this run"
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
      rows.push(["link model", `${link.model} — ${link.description}`]);
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
          "NO — the wire departs from the law the detector was given"
        ),
      ]);
    }
    const box = h("div", { class: "truth" }, [
      h("h3", { text: "Harness ground truth — not visible to the detector" }),
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
          "nothing else — no session object, no adversary log, no harness " +
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
      return panel("Channel — QBER and CHSH per link", "not evaluated", [
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
          unavailable: link.chsh_unavailable || "no CHSH statistic here",
        });
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
      "Channel — QBER and CHSH per link",
      "per link and per message bit, never pooled",
      [
        h("p", {
          class: "note",
          text:
            "Symmetrisation smears the records but never the check logs, so a " +
            "per-link reading is the only one that both detects a " +
            "party-targeted attack and attributes it. Pooling two links would " +
            "report the average of two channels and detect neither — which is " +
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
            "perfectly honest run — read the interval, and read Signals for " +
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
          unavailable: "denied the evidence — nothing to plot",
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
          "Whether one bit is a matter of record on the transcript — the " +
          "Signals and Verifiers panels — and never of a bar being shorter " +
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
          Fmt.flag(floors.meets_every_floor, "yes", "NO — see Signals"),
        ],
        [
          "floors degenerate?",
          Fmt.flag(
            floors.degenerate,
            "YES — at this key length the floors carry no claim",
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
        surety.appendChild(token("withheld", "OUT OF MODEL — (AUTH)"));
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
              )} — withheld, never refuted.`,
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
          "(AUTH) — the classical channel Alice authenticates over is assumed " +
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
      "every hypothesis, every run — a missing row reads as one ruled out",
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
              "P(any signal | honest) — THE NUMBER TO QUOTE"
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
                      "the smallest bound among the signals that DID fire — a " +
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
                text: "none — this run is not a repudiation experiment",
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
              "NO — both collapse at this length",
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
            "parameters is a number close to one — which is not a bound on " +
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
          "The two count-exchange orderings answer different questions — one " +
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
      "not evaluated — which is not the same as passed",
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
                    "NO — about four minutes per session"
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
                    "and with it whether the floors mean anything",
                }),
                h("thead", {}, [
                  h("tr", {}, [
                    h("th", { text: "" }),
                    h("th", { class: "numeric", text: "demo" }),
                    h("th", { class: "numeric", text: "headline" }),
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
   * Assembly
   * ---------------------------------------------------------------------- */

  /**
   * Render a whole `POST /api/run` response into a container.
   *
   * @param {HTMLElement} target
   * @param {Object} payload
   * @param {Object} context `{defaults, attacks, constants}`.
   * @returns {void}
   */
  function run(target, payload, context) {
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
    target.appendChild(verdictStrip(payload));
    const abort = noVerdictBanner(payload);
    if (abort) {
      target.appendChild(abort);
    }
    nullBanners(payload, context).forEach(function (node) {
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
    target.appendChild(summaryPanel(payload));
    target.appendChild(headlineParams(context.defaults));
  }

  return {
    banner: banner,
    h: h,
    headlineParams: headlineParams,
    kv: kv,
    notSupplied: notSupplied,
    panel: panel,
    run: run,
    token: token,
  };
})();
