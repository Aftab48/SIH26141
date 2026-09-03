/* contract.js -- what the API promised, and what it actually sent.
 *
 * The two halves of this dashboard were built in parallel against a fixed
 * contract. Fixed contracts drift. When one does, the frontend has exactly two
 * options for a panel whose number never arrived:
 *
 *   (a) invent the number -- compute it from what did arrive;
 *   (b) say, on the screen, that the API did not supply it.
 *
 * (a) is the D8 violation this whole phase exists to prevent, and it is the
 * comfortable option, which is why it is not available: nothing in this file
 * or any other can derive a missing quantity. So the page does (b), loudly, in
 * place of the panel -- a red dashed box naming the field. A judge seeing that
 * box learns something true. A judge seeing a plausible number computed in
 * JavaScript learns something false and has no way to tell.
 *
 * `data/api-contract.json` is the manifest both this file and
 * `tests/test_web_frontend.py` read, so the names here and the names the tests
 * check are one list rather than two that drift.
 */

const Contract = (function () {
  "use strict";

  let manifest = null;

  /**
   * Load the manifest. Called once at start-up.
   *
   * @param {Object} loaded Parsed `data/api-contract.json`.
   * @returns {void}
   */
  function install(loaded) {
    manifest = loaded;
  }

  /**
   * Return the manifest, or an empty object before it has loaded.
   *
   * @returns {Object}
   */
  function spec() {
    return manifest || {};
  }

  /**
   * Return the names in `names` that `object` does not carry.
   *
   * A field explicitly set to `null` counts as PRESENT: the API saying "there
   * is no repudiation guarantee on this run" is an answer, and the screen
   * renders it as one. Only a field that never arrived is missing.
   *
   * @param {Object|null|undefined} object
   * @param {Array<string>} names
   * @returns {Array<string>}
   */
  function missing(object, names) {
    if (!object || typeof object !== "object") {
      return names.slice();
    }
    const absent = [];
    names.forEach(function (name) {
      if (!Object.prototype.hasOwnProperty.call(object, name)) {
        absent.push(name);
      }
    });
    return absent;
  }

  /**
   * Check a whole `POST /api/run` response against the manifest.
   *
   * @param {Object} payload
   * @returns {{ok: boolean, problems: Array<string>}}
   *   `problems` are human sentences naming a path, ready to be rendered.
   */
  function checkRun(payload) {
    const problems = [];
    const rules = spec();
    const top = (rules.endpoints && rules.endpoints.run) || {};

    missing(payload, top.required || []).forEach(function (name) {
      problems.push(`the response has no "${name}"`);
    });

    const detection = payload ? payload.detection : null;
    const detectionRules = rules.detection || {};
    missing(detection, detectionRules.required || []).forEach(function (name) {
      problems.push(`detection has no "${name}"`);
    });
    if (detection && detection.budget) {
      missing(detection.budget, detectionRules.budget_required || []).forEach(
        function (name) {
          problems.push(`detection.budget has no "${name}"`);
        }
      );
    }
    if (detection && Array.isArray(detection.signals)) {
      detection.signals.forEach(function (signal, index) {
        missing(signal, detectionRules.signal_required || []).forEach(
          function (name) {
            problems.push(`detection.signals[${index}] has no "${name}"`);
          }
        );
      });
    }
    if (detection && Array.isArray(detection.attributions)) {
      detection.attributions.forEach(function (row, index) {
        missing(row, detectionRules.attribution_required || []).forEach(
          function (name) {
            problems.push(`detection.attributions[${index}] has no "${name}"`);
          }
        );
      });
    }

    const runRules = rules.run_facts || {};
    missing(payload ? payload.run : null, runRules.required || []).forEach(
      function (name) {
        problems.push(`run has no "${name}"`);
      }
    );

    const truthRules = rules.ground_truth || {};
    missing(
      payload ? payload.ground_truth : null,
      truthRules.required || []
    ).forEach(function (name) {
      problems.push(`ground_truth has no "${name}"`);
    });

    const timingRules = rules.timings || {};
    missing(payload ? payload.timings : null, timingRules.required || []).forEach(
      function (name) {
        problems.push(`timings has no "${name}"`);
      }
    );

    return { ok: problems.length === 0, problems: problems };
  }

  /**
   * Read one field, or record that it was not supplied.
   *
   * Use this wherever a panel needs a value that might be absent. It never
   * substitutes anything: the caller gets `undefined` and the sentinel is
   * pushed onto `report`, which the panel then renders as a visible marker.
   *
   * @param {Object|null|undefined} object
   * @param {string} name
   * @param {string} path A readable path for the on-screen marker.
   * @param {Array<string>} report Collected sentinels.
   * @returns {*}
   */
  function field(object, name, path, report) {
    if (
      object &&
      typeof object === "object" &&
      Object.prototype.hasOwnProperty.call(object, name)
    ) {
      return object[name];
    }
    report.push(`${path}.${name}`);
    return undefined;
  }

  return {
    checkRun: checkRun,
    field: field,
    install: install,
    missing: missing,
    spec: spec,
  };
})();
