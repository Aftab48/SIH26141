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
    // The run every run-scoped view is about, and how to introduce it.
    payload: null,
    payloadTitle: null,
    payloadWhy: null,
    payloadSource: null,
    selectedFile: null,
    // True for exactly one render after a run is chosen: the replay plays once
    // per selection, not every time someone comes back to the session view.
    autoplay: false,
  };

  /**
   * The bundle every view is rendered against.
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
   * The roster
   * ---------------------------------------------------------------------- */

  /** How each roster entry is introduced: never a verdict colour. */
  const KIND = {
    "not-an-attack": { word: "Baseline", css: "is-baseline" },
    detectable: { word: "Attack", css: "is-attack" },
    "undetectable-by-construction": {
      word: "Undetectable by design",
      css: "is-hidden",
    },
  };

  /**
   * One roster entry by key, or null.
   *
   * @param {string} key
   * @returns {Object|null}
   */
  function rosterEntry(key) {
    let found = null;
    (state.attacks || []).forEach(function (entry) {
      if (found === null && entry.key === key) {
        found = entry;
      }
    });
    return found;
  }

  /* ---------------------------------------------------------------------- *
   * Run a session
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
   * form's starting position is the service's rather than numbers typed into
   * this file. A field the API does not publish starts empty and the API
   * refuses the submission, which is the correct failure.
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
   * One numeric setting, with the API's own range beside it.
   *
   * @param {string} id
   * @param {string} label
   * @param {string} step
   * @param {string} [hint]
   * @returns {HTMLElement}
   */
  function numberField(id, label, step, hint) {
    const caps = capsFor(id);
    const attrs = { type: "number", value: startingValue(id), step: step };
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
        : `${caps.minimum} to ${caps.maximum}`;
    return h("div", { class: "field" }, [
      h("label", { text: label, attrs: { for: id } }),
      input,
      h("span", { class: "field-hint", text: range }),
      hint ? h("span", { class: "field-hint", text: hint }) : null,
    ]);
  }

  /**
   * The Run a session view.
   *
   * @returns {HTMLElement}
   */
  function controls() {
    const detail = h("p", { class: "adversary-detail" });
    const grid = h("div", {
      class: "adversary-grid",
      attrs: { role: "radiogroup", "aria-label": "Adversary" },
    });
    const chosen = startingValue("attack");
    let anyChecked = false;
    (state.attacks || []).forEach(function (entry) {
      const kind = KIND[entry.detectable] || { word: "", css: "" };
      const radio = h("input", {
        attrs: { type: "radio", name: "attack", value: entry.key },
      });
      if (entry.key === chosen) {
        radio.checked = true;
        anyChecked = true;
        detail.textContent = entry.summary || "";
      }
      radio.addEventListener("change", function () {
        detail.textContent = entry.summary || "";
      });
      grid.appendChild(
        h("label", { class: "adversary-tile" }, [
          radio,
          h("span", { class: "tile-name", text: entry.label }),
          h("span", { class: `tile-kind ${kind.css}`, text: kind.word }),
        ])
      );
    });
    if (!anyChecked) {
      const first = grid.querySelector('input[name="attack"]');
      if (first) {
        first.checked = true;
      }
    }

    // The roster comes from the API's own limits block where it publishes
    // one, so a third ordering added upstream appears here without an edit.
    const timings = capsFor("count_exchange_timing").values || [
      "before-forwarding",
      "after-forwarding",
    ];
    const timingSelect = h("select", {});
    timingSelect.id = "count_exchange_timing";
    timings.forEach(function (value) {
      const option = h("option", { text: value, attrs: { value: value } });
      if (value === startingValue("count_exchange_timing")) {
        option.selected = true;
      }
      timingSelect.appendChild(option);
    });

    const runButton = h("button", {
      class: "run-button",
      text: "Run session",
      attrs: { type: "button", id: "run" },
    });
    runButton.addEventListener("click", startLiveRun);

    const limits = (state.defaults && state.defaults.limits) || {};

    return h("div", { class: "run-view" }, [
      h("header", { class: "page-head" }, [
        h("h1", { text: "Run a session" }),
        h("p", {
          text:
            "Choose an adversary and settings. The server generates a real " +
            "session and the detector scores it, usually within seconds. " +
            "Settings outside a range are refused, never adjusted.",
        }),
      ]),
      state.mode === "live"
        ? null
        : h("p", {
            class: "offline-note",
            text:
              "The live service is not answering, so no session can be run " +
              "right now. The recorded scenarios still work.",
          }),
      h("section", { class: "sheet" }, [
        h("h2", { text: "Adversary" }),
        grid,
        detail,
      ]),
      h("section", { class: "sheet" }, [
        h("h2", { text: "Settings" }),
        h("div", { class: "field-row" }, [
          numberField("key_length", "Key length", "1"),
          numberField(
            "check_fraction",
            "Share of positions spent checking the link",
            "0.05"
          ),
          numberField(
            "noise",
            "Noise on the link",
            "0.005",
            "With noise above zero, set both noise assumptions under " +
              "Advanced, or an honest run will still raise an alarm."
          ),
        ]),
        h("details", { class: "advanced" }, [
          h("summary", { text: "Advanced settings" }),
          // The two nulls are ONE instruction and are labelled as one. Setting
          // only the first leaves an honest run over a noisy link detected,
          // with 'honest' ruled out and an adversary named, 12/12 at L = 192
          // over twelve seeds.
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
          h("div", { class: "field-row" }, [
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
          ]),
          h("div", { class: "field-row" }, [
            numberField("eps", "Alarm budget, eps", "any"),
            h("div", { class: "field" }, [
              h("label", {
                text: "When counts are compared",
                attrs: { for: "count_exchange_timing" },
              }),
              timingSelect,
              h("span", {
                class: "field-hint",
                text:
                  "The two orders answer different questions: one is a " +
                  "forgery, the other a denial of service.",
              }),
            ]),
            numberField("seed", "Random seed", "1"),
          ]),
        ]),
      ]),
      h("div", { class: "run-row" }, [
        runButton,
        h("div", {
          class: "run-status",
          text: "Ready",
          attrs: { id: "run-status", role: "status", "aria-live": "polite" },
        }),
      ]),
      limits.max_concurrent_runs === undefined
        ? null
        : h("p", {
            class: "field-hint",
            text:
              `The server runs ${limits.max_concurrent_runs} session(s) at a ` +
              `time and refuses the rest straight away rather than queueing ` +
              `them.`,
          }),
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
   * The scenario rail: every recorded run, one click each.
   *
   * Attack scenarios carry a hazard mark and baselines carry none. That mark
   * says what the SCENARIO is, taken from the roster, and is deliberately not
   * a verdict colour: the rail must not tell a room what the detector will
   * conclude before the replay shows it.
   *
   * @returns {HTMLElement}
   */
  function recordedList() {
    const rail = h("div", { class: "scenario-rail" });
    const list = h("ul", { class: "scenario-list" });
    (state.recorded || []).forEach(function (entry) {
      const held = Object.prototype.hasOwnProperty.call(
        state.recordedPayloads,
        entry.file
      );
      const roster = rosterEntry(entry.attack);
      const attack = roster !== null && roster.detectable !== "not-an-attack";
      const current = state.selectedFile === entry.file;
      const button = h("button", {
        class: `scenario ${current ? "is-current" : ""} ${
          attack ? "is-attack" : ""
        } ${held ? "" : "is-missing"}`,
        attrs: {
          type: "button",
          title: entry.why,
          "aria-pressed": current ? "true" : "false",
          "aria-label": `${entry.label}${attack ? ", attack scenario" : ""}${
            held ? "" : ", not loaded"
          }`,
        },
      }, [
        attack
          ? h("span", { class: "scenario-mark", attrs: { "aria-hidden": "true" } })
          : null,
        h("span", { text: entry.label }),
      ]);
      button.addEventListener("click", function () {
        showRecorded(entry);
      });
      list.appendChild(h("li", {}, [button]));
    });
    const total = (state.recorded || []).length;
    rail.appendChild(list);
    rail.appendChild(
      h("p", {
        class:
          total > 0 && state.recordedHeld === total
            ? "held-note"
            : "held-note is-short",
        text:
          total === 0
            ? "No recorded scenarios: the service that serves them did not " +
              "answer. Start the server and reload."
            : `${state.recordedHeld} of ${total} held in this page's memory, ` +
              `so they keep working if the service stops.`,
      })
    );
    return rail;
  }

  /**
   * Show one recorded run, from memory.
   *
   * No fetch here, by design: this is the path a presenter falls back to when
   * the service has died, and it must not depend on the thing that died.
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
    hold(payload, {
      title: entry.label,
      why: entry.why,
      source: "Recorded run",
      file: entry.file,
    });
    setStatus(`recorded run shown: ${entry.label} (from memory)`, "");
    go("session");
  }

  /* ---------------------------------------------------------------------- *
   * Live runs
   * ---------------------------------------------------------------------- */

  /**
   * Set the status line, where the Run view is showing one.
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
   * Report that nothing answered, in the view AND in the top bar.
   *
   * ONE function, called by every path that can discover the service is gone,
   * because a repaint that lives inside one branch of one function is a fix
   * for one branch of one function.
   *
   * @param {string} message What failed, verbatim.
   * @param {Object} request What was being asked for.
   * @returns {void}
   */
  function noteTransportFailure(message, request) {
    clearHeld();
    Render.refused(
      document.getElementById("view"),
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
      // A click that started no run must not leave the previous run's verdict
      // standing: a presenter who presses Run and sees an alarm has been told
      // a run happened.
      noteTransportFailure(
        "The API is not reachable, so no live run was started. Nothing was " +
          "refused and nothing was scored. The recorded scenarios are held " +
          "in this page's memory and still work.",
        readControls()
      );
      setStatus(
        "The service is not reachable, so no session can be run. The " +
          "recorded scenarios still work.",
        "failed"
      );
      return;
    }
    const body = readControls();
    const button = document.getElementById("run");
    state.busy = true;
    button.disabled = true;
    setStatus(
      `Running ${body.attack} at key length ${body.key_length}. Generating ` +
        `the session is the slow part; detection takes milliseconds.`,
      "busy"
    );
    getJson("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
      .then(function (payload) {
        const roster = rosterEntry(body.attack);
        hold(payload, {
          title: roster ? roster.label : body.attack,
          why: "A session generated just now, with the settings you chose.",
          source: "Live run",
          file: null,
        });
        setStatus("Session complete", "");
        go("session");
      })
      .catch(function (error) {
        // `getJson` throws "HTTP <status> ..." when the server ANSWERED -- a
        // 400 from a cap or a 503 from the run gate is the service working as
        // designed -- and anything else means the fetch itself failed.
        // Repainting the top bar on an HTTP error would announce a dead API
        // every time somebody typed a key length over the ceiling.
        if (error.message.indexOf("HTTP ") === 0) {
          clearHeld();
          Render.refused(
            document.getElementById("view"),
            error.message,
            body,
            "refused"
          );
          // The service answered, so the form is still the way forward: put
          // it back under the refusal rather than making the operator find it.
          document.getElementById("view").appendChild(controls());
          setStatus(`The run was refused: ${error.message}`, "failed");
        } else {
          noteTransportFailure(error.message, body);
          setStatus(
            `Nothing answered (${error.message}). The recorded scenarios ` +
              `still work.`,
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
   * Views
   * ---------------------------------------------------------------------- */

  /**
   * The views, in nav order. `needsRun` marks those that are about a run.
   */
  const VIEWS = [
    { id: "session", label: "Session", needsRun: true },
    { id: "evidence", label: "Evidence", needsRun: true },
    { id: "proof", label: "Proof", needsRun: true },
    { id: "report", label: "Full report", needsRun: true },
  ];

  /**
   * The view the URL asks for, defaulting to the session.
   *
   * A hash route and not a path, because the service has no router: a deep
   * link to `/proof` would 404 on reload.
   *
   * @returns {string}
   */
  function routeId() {
    const asked = String(window.location.hash).replace("#/", "");
    if (asked === "run") {
      return "run";
    }
    let found = "session";
    VIEWS.forEach(function (entry) {
      if (entry.id === asked) {
        found = entry.id;
      }
    });
    return found;
  }

  /**
   * Navigate. Writing the hash triggers the render through `hashchange`, so
   * there is one path into a repaint.
   *
   * @param {string} id
   * @returns {void}
   */
  function go(id) {
    if (String(window.location.hash) === `#/${id}`) {
      renderRoute();
      return;
    }
    window.location.hash = `#/${id}`;
  }

  /**
   * Hold one run as the subject of every run-scoped view.
   *
   * @param {Object} payload
   * @param {{title: string, why: string, source: string, file: ?string}} meta
   * @returns {void}
   */
  function hold(payload, meta) {
    state.payload = payload;
    state.payloadTitle = meta.title;
    state.payloadWhy = meta.why;
    state.payloadSource = meta.source;
    state.selectedFile = meta.file;
    state.autoplay = true;
  }

  /**
   * Drop the held run, so nothing stale stands under a failure.
   *
   * @returns {void}
   */
  function clearHeld() {
    Render.stop();
    state.payload = null;
    state.selectedFile = null;
    state.autoplay = false;
    paintNav();
  }

  /**
   * Build the view switch. Run-scoped views are disabled until a run is held.
   *
   * @returns {void}
   */
  function paintNav() {
    const nav = document.getElementById("pages");
    if (!nav) {
      return;
    }
    const here = routeId();
    nav.textContent = "";
    const tabs = h("div", { class: "view-tabs" });
    VIEWS.forEach(function (entry) {
      const locked = entry.needsRun && !state.payload;
      const button = h("button", {
        class: `view-tab ${entry.id === here ? "is-current" : ""}`,
        text: entry.label,
        attrs: {
          type: "button",
          "aria-current": entry.id === here ? "page" : "false",
        },
      });
      button.disabled = locked;
      button.addEventListener("click", function () {
        go(entry.id);
      });
      tabs.appendChild(button);
    });
    nav.appendChild(tabs);
    const runLink = h("button", {
      class: `view-action ${here === "run" ? "is-current" : ""}`,
      text: "Run a session",
      attrs: {
        type: "button",
        "aria-current": here === "run" ? "page" : "false",
      },
    });
    runLink.addEventListener("click", function () {
      go("run");
    });
    nav.appendChild(runLink);
  }

  /**
   * Render whatever the hash asks for.
   *
   * @returns {void}
   */
  function renderRoute() {
    const view = document.getElementById("view");
    const rail = document.getElementById("scenarios");
    if (!view) {
      return;
    }
    const here = routeId();
    paintNav();
    if (rail) {
      rail.textContent = "";
      rail.hidden = here === "run";
      if (here !== "run") {
        rail.appendChild(recordedList());
      }
    }
    if (here === "run") {
      Render.stop();
      view.textContent = "";
      view.appendChild(controls());
      window.scrollTo(0, 0);
      return;
    }
    if (!state.payload) {
      Render.stop();
      view.textContent = "";
      const start = h("button", {
        class: "run-button",
        text: "Run a session",
        attrs: { type: "button" },
      });
      start.addEventListener("click", function () {
        go("run");
      });
      view.appendChild(
        h("div", { class: "empty-state" }, [
          h("h1", { text: "Pick a scenario to replay" }),
          h("p", {
            text:
              "Choose one of the recorded scenarios above, or run a new " +
              "session against the live service.",
          }),
          start,
        ])
      );
      return;
    }
    Render.page(view, here, state.payload, context(), {
      autoplay: here === "session" && state.autoplay,
      title: state.payloadTitle,
      description: state.payloadWhy,
      source: state.payloadSource,
    });
    if (here === "session") {
      state.autoplay = false;
    }
    window.scrollTo(0, 0);
  }

  /* ---------------------------------------------------------------------- *
   * Start-up
   * ---------------------------------------------------------------------- */

  /**
   * Show which mode the page is in, in the top bar, always.
   *
   * THREE STATES, NOT TWO. `RECORDED ONLY` is a promise that there are
   * recorded runs to fall back to, and on a COLD load against a dead service
   * that promise is empty.
   *
   * @returns {void}
   */
  function paintMode() {
    const chip = document.getElementById("mode-chip");
    if (!chip) {
      return;
    }
    chip.className = `mode-chip is-${state.mode}`;
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
    chip.className = "mode-chip is-dead";
    chip.textContent = "NOTHING LIVE: NO API AND NO RECORDED RUNS";
    chip.title =
      "the service is not answering and no recorded run was loaded, so " +
      "there is nothing on this page to show. Start the server and reload.";
  }

  /**
   * How often the top bar re-checks that the service is really there, in ms.
   */
  const HEALTH_INTERVAL_MS = 5000;

  /**
   * Keep the top bar's claim true by ASKING, not by waiting to be surprised.
   *
   * Recorded runs render from memory, so nothing on that path can fail and
   * revise the chip. `/api/health` is the liveness check the service publishes
   * for exactly this, and restarting the server brings the chip back to
   * `LIVE API` by itself.
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
   * The class goes on the ROOT element: `--scale` is read by the `html` rule,
   * and a custom property set on `<body>` is invisible to a rule matching
   * `<html>`.
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
   * Load the contract and the constants, then the API, falling back to the
   * recordings, then open on the first recorded scenario.
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
          /* Views that needed one say the file was not served. */
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
        // Open on the first scenario that is actually held, so the room sees
        // the bench rather than an empty page.
        let opening = null;
        (state.recorded || []).forEach(function (entry) {
          if (opening === null && state.recordedPayloads[entry.file]) {
            opening = entry;
          }
        });
        if (opening !== null) {
          hold(state.recordedPayloads[opening.file], {
            title: opening.label,
            why: opening.why,
            source: "Recorded run",
            file: opening.file,
          });
        }
        window.addEventListener("hashchange", renderRoute);
        renderRoute();
        if (state.mode !== "live" && state.recordedHeld === 0) {
          // A cold load against a dead service. The page is here because the
          // browser had it cached; nothing behind it is.
          const view = document.getElementById("view");
          view.insertBefore(
            Render.banner("alarm", "⚠", "There is nothing to show", [
              "This page loaded from the browser's cache. The service that " +
                "serves it is not answering, so there is no API to run " +
                "against and no recorded run was loaded either, the " +
                "recordings are served by that same process.",
              "Nothing on this page is a result. Start the server and reload.",
            ]),
            view.firstChild
          );
        }
        watchService();
      });
  }

  return { boot: boot, context: context, state: state };
})();

document.addEventListener("DOMContentLoaded", App.boot);
