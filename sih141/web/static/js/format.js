/* format.js -- turning API numbers into strings, and nothing else.
 *
 * D8: THE FRONTEND COMPUTES NOTHING. This file is where that rule is at its
 * most tempting to break, so it is also where it is stated most plainly.
 *
 * Everything here takes a value the API supplied and returns a STRING. Not one
 * function combines two values, scales one, converts a rate to a percentage,
 * takes a ratio, or decides anything. There is deliberately no `percent()`:
 * writing "1.66%" from 0.0166 is a multiplication, and a multiplication on a
 * screen is a number outside every test this project has. Rates are shown as
 * rates.
 *
 * Rounding here is DISPLAY rounding and is pinned to what Python already does:
 * `exp()` renders four significant figures in the mantissa, which is the
 * `{:.4e}` that `Detection.summary()` prints, so the figure in a chip and the
 * figure in the detector's own summary block are the same string. Nothing is
 * ever rounded to change a comparison -- no threshold is applied here, because
 * no threshold is applied anywhere in this frontend.
 *
 * A null or undefined never becomes a zero. It becomes "n/a" and, where it
 * matters, a word: "no verdict", "not evaluated", "not supplied by the API". A
 * zero on a screen is a claim, and the absence of a number is not one.
 */

/* eslint-disable no-unused-vars */
const Fmt = (function () {
  "use strict";

  /** The mark used wherever a value is genuinely absent. */
  const ABSENT = "n/a";

  /**
   * Return true when a value is a finite number the API actually supplied.
   *
   * @param {*} value
   * @returns {boolean}
   */
  function present(value) {
    return typeof value === "number" && isFinite(value);
  }

  /**
   * Render a probability or bound in scientific notation, four figures.
   *
   * Matches Python's `{:.4e}`, so this string and the one inside
   * `detection.summary` are identical for the same value.
   *
   * @param {number|null|undefined} value
   * @returns {string}
   */
  function exp(value) {
    if (!present(value)) {
      return ABSENT;
    }
    // JavaScript writes "1.0000e-9" where Python's {:.4e} writes "1.0000e-09".
    // The padding matters: the same figure appears verbatim in the detector's
    // own summary block a few panels down, and two spellings of one number on
    // one screen is a reader wondering whether they are two numbers.
    //
    // Done by slicing rather than by a regular expression, and deliberately:
    // a regex literal is the one JavaScript construct a text-level scanner
    // cannot reliably tell from a division, and the scanner in
    // tests/test_web_frontend.py is what enforces D8 over this whole
    // directory. There is no regex literal anywhere in this frontend.
    const parts = value.toExponential(4).split("e");
    const sign = parts[1].slice(0, 1);
    const digits = parts[1].slice(1);
    const pad = digits.length === 1 ? "0" : "";
    return `${parts[0]}e${sign}${pad}${digits}`;
  }

  /** Superscript glyphs for an exponent, so a bound reads as a number. */
  const SUPERSCRIPT = {
    0: "⁰",
    1: "¹",
    2: "²",
    3: "³",
    4: "⁴",
    5: "⁵",
    6: "⁶",
    7: "⁷",
    8: "⁸",
    9: "⁹",
    "-": "⁻",
    "+": "",
  };

  /**
   * Render a probability for a room to read: `3.86 × 10⁻¹⁰`.
   *
   * The same value `exp` renders as `3.8649e-10`, at three figures instead of
   * five. That is the right trade on a screen someone reads from across a
   * hall, and the wrong one in the full report, which is why this is a second
   * function and `exp` is untouched: the report still prints the figure
   * exactly as the detector's own summary does.
   *
   * @param {number|null|undefined} value
   * @returns {string}
   */
  function sci(value) {
    if (!present(value)) {
      return ABSENT;
    }
    if (value === 0) {
      return "0";
    }
    const parts = value.toExponential(2).split("e");
    if (parts[1] === "+0") {
      return parts[0];
    }
    const power = parts[1]
      .split("")
      .map(function (char) {
        return SUPERSCRIPT[char];
      })
      .join("");
    return `${parts[0]} × 10${power}`;
  }

  /**
   * Render a value with a fixed number of decimal places.
   *
   * @param {number|null|undefined} value
   * @param {number} places
   * @returns {string}
   */
  function fixed(value, places) {
    if (!present(value)) {
      return ABSENT;
    }
    return value.toFixed(places);
  }

  /**
   * Render a rate (QBER, mismatch rate) as a rate. Never as a percentage.
   *
   * @param {number|null|undefined} value
   * @returns {string}
   */
  function rate(value) {
    return fixed(value, 6);
  }

  /**
   * Render a CHSH-scale quantity.
   *
   * @param {number|null|undefined} value
   * @returns {string}
   */
  function chsh(value) {
    return fixed(value, 4);
  }

  /**
   * Render an integer count with thousands separators.
   *
   * @param {number|null|undefined} value
   * @returns {string}
   */
  function count(value) {
    if (!present(value)) {
      return ABSENT;
    }
    return value.toLocaleString("en-US");
  }

  /**
   * Render a duration the API measured, in milliseconds.
   *
   * @param {number|null|undefined} value
   * @returns {string}
   */
  function millis(value) {
    if (!present(value)) {
      return ABSENT;
    }
    return `${value.toFixed(1)} ms`;
  }

  /**
   * Render an interval the API supplied, as an interval.
   *
   * @param {{low: number, high: number, confidence: number,
   *          method: string}|null|undefined} interval
   * @param {function(number): string} render
   * @returns {string}
   */
  function interval(interval_, render) {
    if (!interval_) {
      return ABSENT;
    }
    const low = render(interval_.low);
    const high = render(interval_.high);
    const conf = interval_.confidence;
    const level = present(conf) ? conf.toFixed(2) : ABSENT;
    return `[${low}, ${high}]  ${interval_.method}, ${level}`;
  }

  /**
   * Render a boolean the API supplied, with words rather than a tick.
   *
   * @param {boolean|null|undefined} value
   * @param {string} yes
   * @param {string} no
   * @returns {string}
   */
  function flag(value, yes, no) {
    if (value === true) {
      return yes;
    }
    if (value === false) {
      return no;
    }
    return ABSENT;
  }

  /**
   * Render a list the API supplied, or say it is empty in words.
   *
   * @param {Array|null|undefined} items
   * @param {string} emptyText
   * @returns {string}
   */
  function list(items, emptyText) {
    if (!items || items.length === 0) {
      return emptyText;
    }
    return items.join(", ");
  }

  /**
   * Render a `[party, message_bit]` link pair as a label.
   *
   * @param {string} party
   * @param {number} bit
   * @returns {string}
   */
  function link(party, bit) {
    return `${party} / bit ${bit}`;
  }

  /**
   * Render an API sentence for running prose.
   *
   * The API spells a dash as " -- " (ASCII, frozen in the contract). On the
   * page that reads as a stand-in em dash, so it becomes a comma. Verbatim
   * blocks (the detector's summary, the budget derivation) do not use this.
   *
   * @param {*} text
   * @returns {string}
   */
  function prose(text) {
    if (text === null || text === undefined) {
      return "";
    }
    return String(text).split(" -- ").join(", ");
  }

  return {
    ABSENT: ABSENT,
    chsh: chsh,
    count: count,
    exp: exp,
    fixed: fixed,
    flag: flag,
    interval: interval,
    link: link,
    list: list,
    millis: millis,
    present: present,
    prose: prose,
    rate: rate,
    sci: sci,
  };
})();
