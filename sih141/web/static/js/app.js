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
 * THE FALLBACK IS HELD IN MEMORY, NOT LEFT TO THE BROWSER CACHE
 * -------------------------------------------------------------
 * Every recorded run is fetched ONCE, at boot, while the service is still
 * alive, and kept in `state.recordedPayloads`. Clicking one after that touches
 * no network at all.
 *
 * That is the difference between a fallback and a hope. The previous version
 * re-fetched `data/recorded/<file>.json` on every click, and the service sends
 * no `Cache-Control`, so whether a click worked after the process died came
 * down to Chrome's heuristic freshness, roughly a tenth of the file's age,
 * which on a tree cloned that morning is a couple of minutes. Measured on a
 * fresh clone: the page loaded, the process was killed, and three recorded runs
 * in a row failed with `Failed to fetch`. The masthead said RECORDED ONLY and
 * the rail's recorded list was the only thing that could have honoured it.
 *
 * The whole set is 365 KB, fetched in parallel behind the first paint, and the
 * rail says how many are actually held, so a partial preload is visible rather
 * than a promise that fails on the click that needs it.
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
    // file name -> the recorded `POST /api/run` response, held from boot so a
    // click never needs the network. See the header.
    recordedPayloads: {},
    recordedHeld: 0,
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
        : `${caps.minimum} to ${caps.maximum}, refused outside, never clamped`;
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
        label.appendChild(Render.token("withheld", "UNDETECTABLE (AUTH)"));
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
        numberField("noise", "noise: the LINK", "0.005"),
        // The two nulls are ONE instruction and are labelled as one. Setting
        // only the first leaves an honest run over a noisy link detected, with
        // 'honest' ruled out and an adversary named, 12/12 at L = 192 over
        // twelve seeds, so a heading that reads as a single "the null" is not
        // a cosmetic problem.
        h("p", {
          class: "warn-note",
          text:
            "TWO NULLS, AND BOTH DEFAULT TO A PERFECT LINK. detect() reads " +
            "the verifiers' mismatch counts against channel_error_rate and " +
            "the published check rounds against tolerated_depolarising. To " +
            "score an honest run over a noisy link against the link, SET " +
            "BOTH: setting either alone leaves the other family scoring " +
            "against a link nobody has, and the run still fires. Neither is " +
            "ever inferred from the transcript.",
        }),
        numberField(
          "channel_error_rate",
          "NULL 1 of 2: channel_error_rate (rate family)",
          "0.005"
        ),
        numberField(
          "tolerated_depolarising",
          "NULL 2 of 2: tolerated_depolarising (channel family)",
          "0.005"
        ),
        numberField("eps", "eps: the budget", "any"),
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
              "orderings answer different questions, one is a forgery, the " +
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
   * Fetch every recorded run into memory, once, at boot.
   *
   * The fallback exists for the moment the service dies mid-demonstration, and
   * a fallback that fetches is not a fallback. Each entry is fetched once here,
   * while the service is up, and every later click reads `recordedPayloads`.
   * A run that failed to preload simply is not held, and the rail says how many
   * are, `13 of 13 held in memory` is a promise the page can keep.
   *
   * @returns {Promise<void>}
   */
  function preloadRecorded() {
    const entries = state.recorded || [];
    return Promise.all(
      entries.map(function (entry) {
        return getJson(`${STATIC}/data/recorded/${entry.file}`)
          .then(function (payload) {
            state.recordedPayloads[entry.file] = payload;
          })
          .catch(function () {
            /* Not held. `recordedHeld` below counts what actually is. */
          });
      })
    ).then(function () {
      state.recordedHeld = Object.keys(state.recordedPayloads).length;
    });
  }

  /**
   * Build the recorded-run list: the walk-through, in order.
   *
   * @returns {HTMLElement}
   */
  function recordedList() {
    const list = h("ul", { class: "recorded-list" });
    (state.recorded || []).forEach(function (entry) {
      const held = Object.prototype.hasOwnProperty.call(
        state.recordedPayloads,
        entry.file
      );
      const button = h("button", { attrs: { type: "button" } }, [
        h("span", { class: "attack-name", text: entry.label }),
        Render.token("neutral", "RECORDED"),
        held ? null : Render.token("withheld", "NOT LOADED"),
        h("span", { class: "attack-why", text: entry.why }),
      ]);
      button.addEventListener("click", function () {
        showRecorded(entry);
      });
      list.appendChild(h("li", {}, [button]));
    });
    const total = (state.recorded || []).length;
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
        h("p", {
          class:
            total > 0 && state.recordedHeld === total ? "note" : "warn-note",
          text:
            total === 0
              ? "NONE. The walk-through is served by the same process as this " +
                "page and it did not answer, so there is nothing here to " +
                "click and no fallback to fall back to. Start the server and " +
                "reload."
              : `${state.recordedHeld} of ${total} held in this page's ` +
                `memory. Held runs render with no network at all, so they ` +
                `keep working if the service stops answering. Anything not ` +
                `held would need the service back.`,
        }),
        list,
      ]),
    ]);
  }

  /**
   * Render one recorded run, from memory.
   *
   * No fetch here, by design: this is the path a presenter falls back to when
   * the service has died, and it must not depend on the thing that died. A run
   * that was not preloaded is reported as not held rather than fetched on the
   * off-chance.
   *
   * @param {Object} entry An `index.json` row.
   * @returns {void}
   */
  function showRecorded(entry) {
    const payload = state.recordedPayloads[entry.file];
    if (!payload) {
      // Never a silent blank and never the previous run left standing.
      noteTransportFailure(
        `${entry.file} was not loaded into this page's memory, and recorded ` +
          `runs are never fetched on click. If the service is running, ` +
          `reload the page to load it.`,
        { recorded_run: entry.file }
      );
      setStatus(`recorded run not held: ${entry.file}`, "failed");
      return;
    }
    Render.run(document.getElementById("stage"), payload, context());
    setStatus(`recorded run shown: ${entry.label} (from memory)`, "");
    window.scrollTo(0, 0);
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
   * Report that nothing answered, on the stage AND in the masthead.
   *
   * ONE function, called by every path that can discover the service is gone,
   * because the previous version had the masthead repaint in exactly one of
   * them. `startLiveRun`'s catch flipped the chip; `showRecorded`'s did not,
   * so clicking three recorded runs against a dead process gave three
   * `Failed to fetch` panels under a masthead still reading `LIVE API`, and
   * the recorded path is the one a presenter falls back to. A fix that lives
   * inside one branch of one function is a fix for one branch of one function.
   *
   * @param {string} message What failed, verbatim.
   * @param {Object} request What was being asked for.
   * @returns {void}
   */
  function noteTransportFailure(message, request) {
    Render.refused(
      document.getElementById("stage"),
      message,
      request,
      "unreachable"
    );
    state.mode = "recorded";
    paintMode();
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
      // Clear the stage too, not only the status line. A click that started no
      // run must not leave the previous run's verdict standing: a presenter
      // who presses Run and sees DETECTED has been told a run happened.
      noteTransportFailure(
        "The API is not reachable, so no live run was started. Nothing was " +
          "refused and nothing was scored. The recorded runs in the rail are " +
          "held in this page's memory and still work.",
        readControls()
      );
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
        // Clear the stage as well as the status line. A refusal that only
        // wrote to the rail left the previous run's verdict on screen under
        // the new parameters, which is the one thing the caps exist to stop.
        //
        // The two failures stay distinguishable, which is why the repaint is
        // guarded rather than unconditional. `getJson` throws "HTTP <status>
        // ..." when the server ANSWERED -- a 400 from a cap or a 503 from the
        // run gate is the service working exactly as designed -- and anything
        // else means the fetch itself failed. Repainting on an HTTP error
        // would announce a dead API every time somebody typed a key_length
        // over the ceiling.
        if (error.message.indexOf("HTTP ") === 0) {
          Render.refused(
            document.getElementById("stage"),
            error.message,
            body,
            "refused"
          );
          setStatus(
            `the run was refused or failed, ${error.message}`,
            "failed"
          );
        } else {
          noteTransportFailure(error.message, body);
          setStatus(
            `nothing answered, ${error.message}. The recorded runs held in ` +
              `memory still work.`,
            "failed"
          );
        }
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
   * THREE STATES, NOT TWO. `RECORDED ONLY` is a promise that there are
   * recorded runs to fall back to, and on a COLD load against a dead service
   * that promise is empty: the page renders from the browser's cache, the chip
   * said `RECORDED ONLY: API NOT REACHABLE`, and the rail held zero recorded
   * runs, because `index.json` is served by the process that is gone. Nothing
   * numeric was wrong on that screen, every control read "range not supplied
   * by the API", but the chip was, and the chip is the one thing a presenter
   * points at to explain what the room is looking at.
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
      chip.title = "the service answered; runs on this page are real";
      return;
    }
    if (state.recordedHeld > 0) {
      chip.textContent = `RECORDED ONLY (${state.recordedHeld}): API NOT REACHABLE`;
      chip.title =
        "the service is not answering; the recorded runs held in this " +
        "page's memory still render, and no live run can be started";
      return;
    }
    chip.textContent = "NOTHING LIVE: NO API AND NO RECORDED RUNS";
    chip.title =
      "the service is not answering and no recorded run was loaded, so " +
      "there is nothing on this page to show. Start the server and reload.";
  }

  /**
   * How often the masthead re-checks that the service is really there, in ms.
   */
  const HEALTH_INTERVAL_MS = 5000;

  /**
   * Keep the masthead's claim true by ASKING, not by waiting to be surprised.
   *
   * The mode used to be decided once at start-up and revised only when
   * something failed. Now that recorded runs render from memory, nothing on
   * the recorded path can fail, so without this the chip would go on reading
   * `LIVE API` after the process died until somebody pressed Run. A masthead
   * that says the API is live is a claim, and a claim on this screen has to be
   * checked. `/api/health` is a few bytes and is the liveness check the service
   * publishes for exactly this.
   *
   * Recovery is handled too: restart the server and the chip goes back to
   * `LIVE API` by itself, which is what an operator who has just fixed
   * something needs to see.
   *
   * @returns {void}
   */
  function watchService() {
    window.setInterval(function () {
      if (state.busy) {
        return;
      }
      getJson("/api/health")
        .then(function (health) {
          if (health && health.ok === true) {
            if (state.mode !== "live") {
              state.mode = "live";
              paintMode();
            }
            return;
          }
          if (state.mode !== "recorded") {
            state.mode = "recorded";
            paintMode();
          }
        })
        .catch(function () {
          if (state.mode !== "recorded") {
            state.mode = "recorded";
            paintMode();
          }
        });
    }, HEALTH_INTERVAL_MS);
  }

  /**
   * Wire the projector-mode toggle. It changes one CSS variable and no number.
   *
   * The class goes on the ROOT element. `--scale` is read by the `html` rule
   * that sets the root font-size, and a custom property set on `<body>` is
   * invisible to a rule matching `<html>`, so toggling the class on the body
   * sets the variable somewhere nothing reads it and the page does not move.
   *
   * @returns {void}
   */
  function wireProjector() {
    const button = document.getElementById("projector");
    if (!button) {
      return;
    }
    button.addEventListener("click", function () {
      const on = document.documentElement.classList.toggle("projector");
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
      "left rail: a live session, or one recorded ahead of time",
      [
        h("p", {
          class: "note",
          text:
            "Start with the honest baseline. Then the same honest run over a " +
            "noisy link, scored against detect()'s default noiseless null: " +
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
        return getJson(`${STATIC}/data/recorded/index.json`)
          .then(function (index) {
            state.recorded = index;
          })
          .then(preloadRecorded);
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
        if (state.mode !== "live" && state.recordedHeld === 0) {
          // A cold load against a dead service. The page is here because the
          // browser had it cached; nothing behind it is. Say that, rather than
          // laying out a walk-through with nothing in it.
          stage.appendChild(
            Render.banner("alarm", "⚠", "There is nothing to show", [
              "This page loaded from the browser's cache. The service that " +
                "serves it is not answering, so there is no API to run " +
                "against and no recorded run was loaded either, the " +
                "recordings are served by that same process.",
              "Nothing below is a result. Every control reads its range as " +
                "not supplied, and no verdict, bound or rate on this page " +
                "came from anywhere. Start the server and reload.",
            ])
          );
        }
        stage.appendChild(opening());
        stage.appendChild(Render.headlineParams(state.defaults));
        watchService();
      });
  }

  return { boot: boot, context: context, state: state };
})();

document.addEventListener("DOMContentLoaded", App.boot);
