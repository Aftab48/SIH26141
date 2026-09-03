/* app.js -- controls, transport, and the two modes.
 *
 * TWO MODES, BECAUSE OF ONE MEASURED FACT
 * ---------------------------------------
 * Detection is free; generating the session is the whole cost. Under roughly
 * L = 1000 a run is interactive. At DEFAULT_PARAMS (L = 115200) one session is
 * about four minutes, which cannot come from a button click. So:
 *
 *   LIVE      the operator picks an adversary and parameters and the server
 *             runs a real session. Every cap on every control is the API's own,
 *             read from `/api/defaults` and printed beside the field, and a
 *             request outside one is REFUSED by the API rather than clamped --
 *             so a run always answers the question that was asked. The button
 *             disables and a running indicator appears for the whole wait; no
 *             click ever starts something long and silent.
 *
 *   RECORDED  runs generated ahead of time by `tools/phase6_fixtures.py`, which
 *             drives this same API and writes its responses verbatim. Every one
 *             is labelled RECORDED on screen, so nothing looks like it was just
 *             computed. This is also what keeps the demonstration alive if the
 *             service dies: the page falls back by itself and says so in the
 *             masthead.
 *
 * The headline parameters are never faked into a run. `/api/defaults` returns
 * them and the bounds they imply -- `family_budget` derives those without
 * running anything -- and the panel says in as many words that no session was
 * run at that length.
 *
 * D8 IN THIS FILE: it reads controls and posts them. `input.valueAsNumber` is a
 * DOM property, so there is not even a `Number()` call here, let alone a
 * calculation; validation and every cap belong to the API, which has to enforce
 * them anyway and is the only side of the wire that can.
 */

const App = (function () {
  "use strict";

  const h = Render.h;

  /** Where the service mounts the frontend's own files. */
  const STATIC = "/static";

  const state = {
    mode: "unknown",
    defaults: null,
    attacks: null,
    constants: null,
    recorded: null,
    busy: false,
  };

  /**
   * The bundle every panel is rendered against.
   *
   * @returns {Object}
   */
  function context() {
    return {
      defaults: state.defaults,
      attacks: state.attacks,
      constants: state.constants,
    };
  }

  /* ---------------------------------------------------------------------- *
   * Transport
   * ---------------------------------------------------------------------- */

  /**
   * Fetch JSON from a same-origin path. Nothing here ever leaves the origin.
   *
   * @param {string} path
   * @param {Object} [options]
   * @returns {Promise<Object>}
   */
  function getJson(path, options) {
    return fetch(path, options).then(function (response) {
      return response.json().then(function (body) {
        if (!response.ok) {
          const detail = body && body.message ? body.message : "";
          throw new Error(`HTTP ${response.status} ${detail}`);
        }
        return body;
      });
    });
  }

  /* ---------------------------------------------------------------------- *
   * Controls
   * ---------------------------------------------------------------------- */

  /**
   * Return one field's cap block from `/api/defaults`, or an empty object.
   *
   * @param {string} name
   * @returns {Object}
   */
  function capsFor(name) {
    const limits = (state.defaults && state.defaults.limits) || {};
    const fields = limits.fields || {};
    return fields[name] || {};
  }

  /**
   * Return the API's own starting value for one request field.
   *
   * `/api/defaults` publishes `params` as a whole default REQUEST, so the
   * form's starting position is the service's rather than five numbers typed
   * into this file. A field the API does not publish starts empty and the API
   * refuses the submission, which is the correct failure: better a refusal
   * naming the field than a silent default nobody chose.
   *
   * @param {string} name
   * @returns {string}
   */
  function startingValue(name) {
    const params = (state.defaults && state.defaults.params) || {};
    if (!Object.prototype.hasOwnProperty.call(params, name)) {
      return "";
    }
    return String(params[name]);
  }

  /**
   * Build one numeric control, with the API's own cap printed beside it.
   *
   * @param {string} id
   * @param {string} label
   * @param {string} step
   * @returns {HTMLElement}
   */
  function numberField(id, label, step) {
    const caps = capsFor(id);
    const attrs = {
      type: "number",
      value: startingValue(id),
      step: step,
    };
    if (caps.minimum !== undefined) {
      attrs.min = String(caps.minimum);
    }
    if (caps.maximum !== undefined) {
      attrs.max = String(caps.maximum);
    }
    const input = h("input", { attrs: attrs });
    input.id = id;
    const range =
      caps.minimum === undefined
        ? "range not supplied by the API"
        : `${caps.minimum} to ${caps.maximum}, refused outside — never clamped`;
    return h("div", { class: "field" }, [
      h("label", { text: label, attrs: { for: id } }),
      input,
      h("span", { class: "cap", text: range }),
      caps.note ? h("span", { class: "cap", text: caps.note }) : null,
    ]);
  }

  /**
   * Build the whole control rail.
   *
   * @returns {HTMLElement}
   */
  function controls() {
    const attackList = h("ul", { class: "attack-list" });
    (state.attacks || []).forEach(function (entry, index) {
      const radio = h("input", {
        attrs: { type: "radio", name: "attack", value: entry.key },
      });
      if (entry.key === startingValue("attack") || index === 0) {
        radio.checked = true;
      }
      const label = h("label", {}, [
        radio,
        h("span", { class: "attack-name", text: entry.label }),
      ]);
      if (entry.detectable === "undetectable-by-construction") {
        label.appendChild(Render.token("withheld", "UNDETECTABLE — (AUTH)"));
      } else if (entry.detectable === "not-an-attack") {
        label.appendChild(Render.token("clean", "BASELINE"));
      } else {
        label.appendChild(Render.token("detected", "DETECTABLE"));
      }
      label.appendChild(h("span", { class: "attack-why", text: entry.summary }));
      if (entry.assumption) {
        label.appendChild(
          h("span", { class: "attack-why", text: entry.assumption })
        );
      }
      attackList.appendChild(h("li", {}, [label]));
    });

    // The roster comes from the API's own limits block where it publishes
    // one, so a third ordering added upstream appears here without an edit.
    const timings = capsFor("count_exchange_timing").values || [
      "before-forwarding",
      "after-forwarding",
    ];
    const chosen = startingValue("count_exchange_timing");
    const timingSelect = h("select", {});
    timingSelect.id = "count_exchange_timing";
    timings.forEach(function (value) {
      const option = h("option", { text: value, attrs: { value: value } });
      if (value === chosen) {
        option.selected = true;
      }
      timingSelect.appendChild(option);
    });

    const runButton = h("button", {
      class: "run-button",
      text: "Run one session",
      attrs: { type: "button", id: "run" },
    });
    runButton.addEventListener("click", startLiveRun);

    const status = h("div", {
      class: "run-status",
      text: "idle",
      attrs: { id: "run-status", role: "status", "aria-live": "polite" },
    });

    const limits = (state.defaults && state.defaults.limits) || {};
    return h("section", { class: "panel" }, [
      h("h2", { text: "Run one session" }, [
        h("span", { class: "hint", text: "every cap below is the API's" }),
      ]),
      h("div", { class: "panel-body" }, [
        h("div", { class: "field" }, [
          h("label", { text: "Adversary" }),
          attackList,
        ]),
        numberField("key_length", "key_length", "1"),
        numberField("check_fraction", "check_fraction", "0.05"),
        numberField("noise", "noise — the LINK", "0.005"),
        numberField(
          "channel_error_rate",
          "channel_error_rate — the NULL (rate family)",
          "0.005"
        ),
        numberField(
          "tolerated_depolarising",
          "tolerated_depolarising — the NULL (channel family)",
          "0.005"
        ),
        numberField("eps", "eps — the budget", "any"),
        h("div", { class: "field" }, [
          h("label", {
            text: "count_exchange_timing",
            attrs: { for: "count_exchange_timing" },
          }),
          timingSelect,
          h("span", {
            class: "cap",
            text:
              "a control and a label, never a thing to average over. The two " +
              "orderings answer different questions — one is a forgery, the " +
              "other a denial of service.",
          }),
        ]),
        numberField("seed", "seed", "1"),
        runButton,
        status,
        limits.max_concurrent_runs === undefined
          ? null
          : h("p", {
              class: "note",
              text:
                `The server accepts ${limits.max_concurrent_runs} concurrent ` +
                `run(s) and refuses the rest immediately rather than parking ` +
                `them behind seconds of simulation with nothing on screen.`,
            }),
      ]),
    ]);
  }

  /**
   * Read the controls. No conversion beyond the DOM's own `valueAsNumber`.
   *
   * @returns {Object} The `POST /api/run` body.
   */
  function readControls() {
    const picked = document.querySelector('input[name="attack"]:checked');
    return {
      attack: picked ? picked.value : "honest",
      key_length: document.getElementById("key_length").valueAsNumber,
      check_fraction: document.getElementById("check_fraction").valueAsNumber,
      noise: document.getElementById("noise").valueAsNumber,
      eps: document.getElementById("eps").valueAsNumber,
      channel_error_rate: document.getElementById("channel_error_rate")
        .valueAsNumber,
      tolerated_depolarising: document.getElementById("tolerated_depolarising")
        .valueAsNumber,
      count_exchange_timing: document.getElementById("count_exchange_timing")
        .value,
      seed: document.getElementById("seed").valueAsNumber,
    };
  }

  /* ---------------------------------------------------------------------- *
   * Recorded runs
   * ---------------------------------------------------------------------- */

  /**
   * Build the recorded-run list: the walk-through, in order.
   *
   * @returns {HTMLElement}
   */
  function recordedList() {
    const list = h("ul", { class: "recorded-list" });
    (state.recorded || []).forEach(function (entry) {
      const button = h("button", { attrs: { type: "button" } }, [
        h("span", { class: "attack-name", text: entry.label }),
        Render.token("neutral", "RECORDED"),
        h("span", { class: "attack-why", text: entry.why }),
      ]);
      button.addEventListener("click", function () {
        showRecorded(entry);
      });
      list.appendChild(h("li", {}, [button]));
    });
    return h("section", { class: "panel" }, [
      h("h2", { text: "Recorded runs" }, [
        h("span", { class: "hint", text: "generated ahead of time, not now" }),
      ]),
      h("div", { class: "panel-body" }, [
        h("p", {
          class: "note",
          text:
            "Produced by tools/phase6_fixtures.py, which drives this same API " +
            "and writes its answers verbatim. They are the walk-through: the " +
            "baseline, then the baseline's own failure mode, then the " +
            "adversaries, then the runs that exist to show what this screen " +
            "must not claim.",
        }),
        list,
      ]),
    ]);
  }

  /**
   * Load and render one recorded run.
   *
   * @param {Object} entry An `index.json` row.
   * @returns {void}
   */
  function showRecorded(entry) {
    setStatus(`loading recorded run: ${entry.label}`, "busy");
    getJson(`${STATIC}/data/recorded/${entry.file}`)
      .then(function (payload) {
        Render.run(document.getElementById("stage"), payload, context());
        setStatus(`recorded run shown: ${entry.label}`, "");
        window.scrollTo(0, 0);
      })
      .catch(function (error) {
        setStatus(`could not load ${entry.file}: ${error.message}`, "failed");
      });
  }

  /* ---------------------------------------------------------------------- *
   * Live runs
   * ---------------------------------------------------------------------- */

  /**
   * Set the status line.
   *
   * @param {string} text
   * @param {string} cls `busy`, `failed`, or empty.
   * @returns {void}
   */
  function setStatus(text, cls) {
    const node = document.getElementById("run-status");
    if (!node) {
      return;
    }
    node.className = `run-status ${cls}`;
    node.textContent = text;
  }

  /**
   * Start one live run. One at a time: a second click is refused rather than
   * queued, because two multi-second sessions racing is how a demo hangs.
   *
   * @returns {void}
   */
  function startLiveRun() {
    if (state.busy) {
      return;
    }
    if (state.mode !== "live") {
      setStatus(
        "the API is not reachable, so no live run can be started. The " +
          "recorded runs below still work.",
        "failed"
      );
      return;
    }
    const body = readControls();
    const button = document.getElementById("run");
    state.busy = true;
    button.disabled = true;
    setStatus(
      `running: ${body.attack}, key_length ${body.key_length}, ` +
        `check_fraction ${body.check_fraction}, noise ${body.noise}, ` +
        `timing ${body.count_exchange_timing}. Generating the session is the ` +
        `slow part; detection is milliseconds.`,
      "busy"
    );
    getJson("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
      .then(function (payload) {
        Render.run(document.getElementById("stage"), payload, context());
        setStatus("live run complete", "");
      })
      .catch(function (error) {
        setStatus(`the run was refused or failed — ${error.message}`, "failed");
      })
      .then(function () {
        state.busy = false;
        button.disabled = false;
      });
  }

  /* ---------------------------------------------------------------------- *
   * Start-up
   * ---------------------------------------------------------------------- */

  /**
   * Show which mode the page is in, in the masthead, always.
   *
   * @returns {void}
   */
  function paintMode() {
    const chip = document.getElementById("mode-chip");
    if (!chip) {
      return;
    }
    if (state.mode === "live") {
      chip.textContent = "LIVE API";
    } else {
      chip.textContent = "RECORDED ONLY — API NOT REACHABLE";
    }
  }

  /**
   * Wire the projector-mode toggle. It changes one CSS variable and no number.
   *
   * @returns {void}
   */
  function wireProjector() {
    const button = document.getElementById("projector");
    if (!button) {
      return;
    }
    button.addEventListener("click", function () {
      const on = document.body.classList.toggle("projector");
      button.setAttribute("aria-pressed", on ? "true" : "false");
    });
  }

  /**
   * The opening panel: what the walk-through is, and the four states.
   *
   * @returns {HTMLElement}
   */
  function opening() {
    return Render.panel(
      "Pick a run",
      "left rail — a live session, or one recorded ahead of time",
      [
        h("p", {
          class: "note",
          text:
            "Start with the honest baseline. Then the same honest run over a " +
            "noisy link, scored against detect()'s default noiseless null — " +
            "which FIRES, correctly, and is this dashboard's worst failure " +
            "mode. Then the adversaries: watch QBER and CHSH move on the " +
            "targeted link only, watch the floors, and watch a denial land as " +
            "a NO VERDICT rather than as a rejection, with the proven bound " +
            "beside the measured numbers throughout.",
        }),
        h("div", { class: "legend" }, [
          h("span", { text: "the states, and none of them is a shade of another:" }),
          Render.token("clean", "NOTHING FIRED / ACCEPTED"),
          Render.token("detected", "DETECTED / REJECTED"),
          Render.token("noverdict", "NO VERDICT"),
          Render.token("withheld", "NOT EVALUATED"),
        ]),
        h("div", { class: "legend" }, [
          h("span", { text: "and the two kinds of number:" }),
          Render.h("span", { class: "num num-proven" }, [
            Render.h("span", { class: "kind", text: "⊢ proven" }),
            Render.h("span", {
              class: "value",
              text: "from a stated null and a named inequality",
            }),
          ]),
          Render.h("span", { class: "num num-measured" }, [
            Render.h("span", { class: "kind", text: "measured" }),
            Render.h("span", {
              class: "value",
              text: "counted over runs, always with its sample size",
            }),
          ]),
        ]),
      ]
    );
  }

  /**
   * Load the contract and the constants, then the API, falling back to the
   * recordings.
   *
   * @returns {void}
   */
  function boot() {
    wireProjector();
    Promise.all([
      getJson(`${STATIC}/data/api-contract.json`)
        .then(function (manifest) {
          Contract.install(manifest);
        })
        .catch(function () {
          /* The page still runs; the contract check passes everything. */
        }),
      getJson(`${STATIC}/data/constants.json`)
        .then(function (constants) {
          state.constants = constants;
        })
        .catch(function () {
          /* Panels that needed one say the file was not served. */
        }),
    ])
      .then(function () {
        return Promise.all([getJson("/api/attacks"), getJson("/api/defaults")])
          .then(function (both) {
            state.attacks = both[0];
            state.defaults = both[1];
            state.mode = "live";
          })
          .catch(function () {
            return Promise.all([
              getJson(`${STATIC}/data/recorded/attacks.json`),
              getJson(`${STATIC}/data/recorded/defaults.json`),
            ]).then(function (both) {
              state.attacks = both[0];
              state.defaults = both[1];
              state.mode = "recorded";
            });
          });
      })
      .then(function () {
        return getJson(`${STATIC}/data/recorded/index.json`).then(
          function (index) {
            state.recorded = index;
          }
        );
      })
      .catch(function () {
        state.recorded = state.recorded || [];
      })
      .then(function () {
        paintMode();
        const rail = document.getElementById("rail");
        rail.textContent = "";
        rail.appendChild(controls());
        rail.appendChild(recordedList());
        const stage = document.getElementById("stage");
        stage.textContent = "";
        stage.appendChild(opening());
        stage.appendChild(Render.headlineParams(state.defaults));
      });
  }

  return { boot: boot, context: context, state: state };
})();

document.addEventListener("DOMContentLoaded", App.boot);
